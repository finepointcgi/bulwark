using System.Reflection;
using Nightjar.Ai;
using Nightjar.Core.Ai;
using Nightjar.Core.Engines;
using Nightjar.Core.Findings;
using Nightjar.Core.Policy;
using Nightjar.Core.Reports;
using Nightjar.Core.Updates;
using Nightjar.Engines.Execution;
using Nightjar.Engines.Gitleaks;
using Nightjar.Engines.Opengrep;
using Nightjar.Engines.Osv;
using Nightjar.Engines.Syft;
using Nightjar.Engines.Trivy;

namespace Nightjar.Cli;

internal static class Cli
{
    internal const int ExitPassed = 0;
    internal const int ExitGateFailed = 1;
    internal const int ExitError = 2;

    private static string Version =>
        typeof(Cli).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion.Split('+')[0] ?? "dev";

    public static async Task<int> RunAsync(string[] args)
    {
        var options = Options.Parse(args);
        try
        {
            return options.Command switch
            {
                "scan" => await ScanAsync(options),
                "pentest" => await PentestCommand.RunAsync(options),
                "engines" when options.Positional.FirstOrDefault() == "watch" => await UpdateCommands.WatchAsync(options),
                "engines" => Engines(options),
                "update" => await UpdateCommands.UpdateAsync(options),
                "canary" => await UpdateCommands.CanaryAsync(options),
                "triage" => TriageCommand.Run(options),
                "monitor" => await MonitorCommand.RunAsync(options),
                "fix" => await FixCommand.RunAsync(options),
                "sbom" => await SbomCommand.RunAsync(options),
                "hook" => HookCommand.Hook(options),
                "precommit" => await HookCommand.PreCommitAsync(options),
                "self-update" => await UpdateCommands.SelfUpdateAsync(options),
                "manifest" => Manifest(options),
                "version" or "--version" => Print(Version),
                _ => Help(),
            };
        }
        catch (Exception e) when (e is not OperationCanceledException)
        {
            Console.Error.WriteLine($"error: {e.Message}");
            return ExitError;
        }
    }

    private static async Task<int> ScanAsync(Options options)
    {
        var path = options.Positional.ElementAtOrDefault(0) ?? ".";
        if (!Directory.Exists(path))
        {
            Console.Error.WriteLine($"error: directory not found: {path}");
            return ExitError;
        }

        await UpdateCommands.AutoUpdateAsync(options);

        var store = ManifestStore.Default();
        var (manifest, isBuiltIn) = store.Load();
        if (isBuiltIn)
        {
            Console.Error.WriteLine("warning: using built-in engine versions (unpinned). Run `nightjar update` to install a signed manifest.");
        }

        var engines = EngineFactory.Create(EngineFactory.Runner(manifest, options), options);

        var quiet = options.Value("format") is "json" or "sarif" && options.Value("output") is null;
        var progress = new Progress<string>(message => { if (!quiet) { Console.Error.WriteLine($"» {message}"); } });

        using var cancel = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) => { e.Cancel = true; cancel.Cancel(); };

        var pipeline = new ScanPipeline(engines, manifest);
        var report = await pipeline.RunAsync(path, progress, cancel.Token);
        (report, var newIds) = TriageCommand.AfterScan(report, options, store.HomeDirectory);
        if (options.Value("ai") is { } provider)
        {
            report = await ReviewWithAiAsync(report, provider, options, progress, cancel.Token);
        }

        var archive = new ReportArchive(store.HomeDirectory);
        var previous = archive.Load(report.Project);
        archive.Save(report);
        new ScanHistory(store.HomeDirectory).Record(report, previous);
        if (pipeline.Sbom is { } sbom)
        {
            archive.SaveSbom(report.Project, sbom); // For `nightjar monitor` and the dashboard's daily re-check.
        }

        var exitCode = await PublishAsync(report, options, newIds);
        return Math.Max(exitCode, QualityGates.Check(report, options));
    }

    /// <summary>
    /// Renders a report in the requested format and applies the quality gate. Shared by scan and pentest.
    /// With <paramref name="newIds"/> (from --since/--baseline) the gate only considers new findings.
    /// </summary>
    internal static async Task<int> PublishAsync(ScanReport report, Options options, IReadOnlySet<string>? newIds = null)
    {
        var rendered = options.Value("format") switch
        {
            "json" => report.ToJson(),
            "sarif" => SarifWriter.Write(report, Version),
            "markdown" or "md" => MarkdownWriter.Write(report, newIds, options.Value("fail-on") ?? "high"),
            "codeclimate" => CodeClimateWriter.Write(report),
            null or "table" => TableWriter.Write(report),
            var other => throw new ArgumentException($"unknown format '{other}' (use table, json, sarif, markdown or codeclimate)"),
        };

        if (options.Value("output") is { } output)
        {
            await File.WriteAllTextAsync(output, rendered);
            Console.Error.WriteLine($"Wrote {output}");
        }
        else
        {
            Console.WriteLine(rendered);
        }

        // CI: extra outputs from the same scan (code scanning upload, PR comment, GitLab MR widget).
        if (options.Value("sarif-output") is { } sarifPath)
        {
            await File.WriteAllTextAsync(sarifPath, SarifWriter.Write(report, Version));
        }

        if (options.Value("summary-output") is { } summaryPath)
        {
            await File.WriteAllTextAsync(summaryPath, MarkdownWriter.Write(report, newIds, options.Value("fail-on") ?? "high"));
        }

        if (options.Value("codeclimate-output") is { } codeClimatePath)
        {
            await File.WriteAllTextAsync(codeClimatePath, CodeClimateWriter.Write(report));
        }

        foreach (var failed in report.Engines.Where(e => !e.Succeeded))
        {
            Console.Error.WriteLine($"warning: {failed.Engine} failed: {failed.Error}");
        }

        var failOn = options.Value("fail-on") ?? "high";
        if (failOn.Equals("none", StringComparison.OrdinalIgnoreCase))
        {
            return ExitPassed;
        }

        var gated = newIds is null ? report.Findings : report.Findings.Where(f => newIds.Contains(f.Id)).ToList();
        if (options.Has("ignore-unimported"))
        {
            var skipped = gated.Count(f => f.Reachability == Reachability.NotImported);
            gated = gated.Where(f => f.Reachability != Reachability.NotImported).ToList();
            Console.Error.WriteLine($"Reachability: {skipped} dependency finding(s) not imported by first-party code excluded from the gate (they may still be reachable through other dependencies).");
        }

        var scope = newIds is null ? "" : " new";
        var gate = new QualityGate(Enum.Parse<Severity>(failOn, ignoreCase: true)).Evaluate(gated);
        Console.Error.WriteLine(gate.Passed
            ? $"Quality gate passed (fail-on {failOn}{(newIds is null ? "" : ", new findings only")})."
            : $"Quality gate FAILED: {gate.Blocking.Count}{scope} finding(s) at {failOn} or above.");
        return gate.Passed ? ExitPassed : ExitGateFailed;
    }

    /// <summary>AI pen-test review: judge whether each finding is actually exploitable in this codebase.</summary>
    private static async Task<ScanReport> ReviewWithAiAsync(
        ScanReport report, string provider, Options options, IProgress<string> progress, CancellationToken cancellationToken)
    {
        using var http = new HttpClient { Timeout = TimeSpan.FromMinutes(10) };
        var llm = CreateLlm(provider, options, http);
        if (llm.IsRemote)
        {
            Console.Error.WriteLine($"notice: AI review sends finding details and source excerpts to {llm.Name}. Use --ai ollama to keep code local.");
        }

        var reviewOptions = new ReviewOptions
        {
            MinSeverity = Enum.Parse<Severity>(options.Value("ai-min-severity") ?? "medium", ignoreCase: true),
            MaxFindings = int.Parse(options.Value("ai-max") ?? "25", System.Globalization.CultureInfo.InvariantCulture),
        };

        progress.Report($"AI review with {llm.Name}...");
        var (reviewed, summary) = await new ExploitabilityReviewer(llm, reviewOptions).ReviewAsync(report, progress, cancellationToken);

        progress.Report($"AI reviewed {summary.Reviewed} finding(s), {summary.Failed} failed, {summary.Skipped} over the --ai-max limit");
        foreach (var error in summary.Errors.Take(5))
        {
            Console.Error.WriteLine($"warning: AI review: {error}");
        }

        return reviewed;
    }

    internal static ILlmClient CreateLlm(string provider, Options options, HttpClient http)
    {
        var model = options.Value("ai-model");
        return provider.ToLowerInvariant() switch
        {
            "claude" => new ClaudeLlmClient(model),
            "claude-code" => new ClaudeCodeLlmClient(model),
            "ollama" => new OllamaLlmClient(http, model ?? OllamaLlmClient.DefaultModel),
            _ => throw new ArgumentException($"unknown AI provider '{provider}' (use claude, claude-code or ollama)"),
        };
    }

    private static int Engines(Options options)
    {
        var store = ManifestStore.Default();
        var (manifest, isBuiltIn) = store.Load();
        var runner = new ToolRunner(manifest, options.Has("container") ? ToolMode.Container : ToolMode.Auto);

        Console.WriteLine($"Manifest: {(isBuiltIn ? "built-in (unsigned)" : store.ManifestPath)}  channel={manifest.Channel}  sequence={manifest.Sequence}");
        foreach (var engine in manifest.Engines)
        {
            Console.WriteLine($"  {engine.Name,-14} {engine.Version,-10} {runner.Describe(engine.Name)}");
        }

        return ExitPassed;
    }


    /// <summary>Maintainer commands for producing signed manifests in the release pipeline.</summary>
    private static int Manifest(Options options)
    {
        switch (options.Positional.ElementAtOrDefault(0))
        {
            case "keygen":
            {
                var directory = options.Positional.ElementAtOrDefault(1) ?? ".";
                Directory.CreateDirectory(directory);
                var (privateKey, publicKey) = ManifestSignature.CreateKeyPair();
                var privatePath = Path.Combine(directory, "nightjar-signing.key");
                if (File.Exists(privatePath))
                {
                    Console.Error.WriteLine($"error: {privatePath} already exists; refusing to overwrite a signing key.");
                    return ExitError;
                }

                File.WriteAllText(privatePath, privateKey);
                if (!OperatingSystem.IsWindows())
                {
                    File.SetUnixFileMode(privatePath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
                }

                File.WriteAllText(Path.Combine(directory, "nightjar-signing.pub"), publicKey);
                Console.WriteLine($"Wrote {privatePath} (keep secret) and nightjar-signing.pub");
                return ExitPassed;
            }

            case "generate":
                return UpdateCommands.Generate(options);

            case "sign":
            {
                var manifestPath = options.Positional.ElementAtOrDefault(1) ?? throw new ArgumentException("usage: nightjar manifest sign <manifest.json> --private-key <key>");
                var keyPath = options.Value("private-key") ?? throw new ArgumentException("--private-key is required");
                var bytes = File.ReadAllBytes(manifestPath);
                EngineManifest.Parse(bytes); // Refuse to sign something the client could not read.
                File.WriteAllText(manifestPath + ".sig", ManifestSignature.Sign(bytes, File.ReadAllText(keyPath)));
                Console.WriteLine($"Wrote {manifestPath}.sig");
                return ExitPassed;
            }

            default:
                Console.Error.WriteLine("usage: nightjar manifest keygen [dir] | nightjar manifest sign <manifest.json> --private-key <key>");
                return ExitError;
        }
    }

    private static int Print(string text)
    {
        Console.WriteLine(text);
        return ExitPassed;
    }

    private static int Help()
    {
        Console.WriteLine($"""
            nightjar {Version} - open-source security and code quality scanning

            usage:
              nightjar scan [path] [--format table|json|sarif] [--output file]
                                  [--fail-on critical|high|medium|low|none] [--ignore-unimported] [--engines a,b] [--container]
                                  [--rules dir1,dir2]   extra Opengrep rule folders
                                  [--history full|off|<range>]  secrets in git history (default full;
                                                        e.g. origin/main..HEAD for just a PR's commits)
                                  [--since <git-ref> | --baseline <report.json|last>]  gate on new findings only
                                  [--min-coverage 80] [--max-duplication 5] [--max-complexity 15]
                                  [--image ref,ref] [--image-include-unfixed]   container images to scan
                                  [--format markdown|codeclimate] [--sarif-output f] [--summary-output f]
                                  [--codeclimate-output f] [--no-update]
                                  [--ai claude|claude-code|ollama] [--ai-model name] [--ai-min-severity medium] [--ai-max 25]
              nightjar triage <id> false-positive|accepted-risk|confirmed|fixed|reset --reason "..."
                                  [--expires yyyy-mm-dd] [--project path] [--shared]   (also in the dashboard)
              nightjar sbom [path] [--format cyclonedx|spdx] [--vex] [--output file]
              nightjar hook install|uninstall      git pre-commit secret scan of staged changes
              nightjar monitor [--project path] [--webhook url] [--fail-on high]
                                  re-check saved SBOMs against new advisories (run daily)
              nightjar fix [path] [--dry-run] [--pr] [--min-severity low]
                                  upgrade vulnerable dependencies to the smallest version that fixes them
              nightjar pentest init [scope.json]    write a scope file to fill in
              nightjar pentest <url> --scope scope.json --i-am-authorized
                                  [--ai claude|claude-code|ollama] [--ai-model name]  AI plans the targeted checks
                                  [--source path]  seed the plan from that project's last `scan --ai`
                                  [--openapi spec.json|url]  also run ZAP's API scan from the spec
                                  [--engines zap,nuclei] [--format ...] [--output file] [--fail-on ...]
              nightjar engines [--container]        show pinned engines and how each will run
              nightjar update [--url url | --from-file manifest.json] [--key public.pem] [--skip-canary]
                                  install a newer signed manifest, canary-check it, roll back on failure
                                  (scan also checks once a day; NIGHTJAR_AUTO_UPDATE=0 or --no-update to opt out)
              nightjar canary [--manifest file]     check every engine still finds the known issues
              nightjar self-update                  install the Nightjar release named in the signed manifest
              nightjar manifest keygen [dir]        (maintainers) create a signing key pair
              nightjar manifest sign <file> --private-key <key>
              nightjar manifest generate --digests file [--image-prefix ...] [--out manifest.json]
              nightjar engines watch [--min-age-days 14] [--base-min-age-days 2] [--only engines|base] [--write]
                                  bump engines.json and engine base images to mature releases
              nightjar version

            exit codes: 0 passed, 1 a gate failed (or monitor found new advisories), 2 error
            """);
        return ExitPassed;
    }
}

