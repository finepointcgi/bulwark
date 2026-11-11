using System.Reflection;
using Bulwark.Ai;
using Bulwark.Core.Ai;
using Bulwark.Core.Engines;
using Bulwark.Core.Findings;
using Bulwark.Core.Policy;
using Bulwark.Core.Reports;
using Bulwark.Core.Updates;
using Bulwark.Engines.Execution;
using Bulwark.Engines.Gitleaks;
using Bulwark.Engines.Opengrep;
using Bulwark.Engines.Osv;
using Bulwark.Engines.Syft;
using Bulwark.Engines.Trivy;

namespace Bulwark.Cli;

internal static class Cli
{
    private const int ExitPassed = 0;
    private const int ExitGateFailed = 1;
    private const int ExitError = 2;

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
                "engines" => Engines(options),
                "update" => await UpdateAsync(options),
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

        var store = ManifestStore.Default();
        var (manifest, isBuiltIn) = store.Load();
        if (isBuiltIn)
        {
            Console.Error.WriteLine("warning: using built-in engine versions (unpinned). Run `bulwark update` to install a signed manifest.");
        }

        var runner = new ToolRunner(manifest, options.Has("container") ? ToolMode.Container : ToolMode.Auto);
        var ruleDirectories = options.Value("rules")?.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries) ?? [];
        foreach (var directory in ruleDirectories.Where(d => !Directory.Exists(d)))
        {
            Console.Error.WriteLine($"error: rules directory not found: {directory}");
            return ExitError;
        }

        IEngine[] engines =
        [
            new SyftEngine(runner, new LicensePolicy()),
            new OsvScannerEngine(runner),
            new GitleaksEngine(runner, HistoryScope.Parse(options.Value("history"))),
            new OpengrepEngine(runner, ruleDirectories),
            new TrivyIacEngine(runner),
        ];
        var only = options.Value("engines")?.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
        if (only is not null)
        {
            engines = engines.Where(e => only.Contains(e.Name, StringComparer.OrdinalIgnoreCase)).ToArray();
        }

        var quiet = options.Value("format") is "json" or "sarif" && options.Value("output") is null;
        var progress = new Progress<string>(message => { if (!quiet) { Console.Error.WriteLine($"» {message}"); } });

        using var cancel = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) => { e.Cancel = true; cancel.Cancel(); };

        var report = await new ScanPipeline(engines, manifest).RunAsync(path, progress, cancel.Token);
        if (options.Value("ai") is { } provider)
        {
            report = await ReviewWithAiAsync(report, provider, options, progress, cancel.Token);
        }

        new ReportArchive(store.HomeDirectory).Save(report);

        var rendered = options.Value("format") switch
        {
            "json" => report.ToJson(),
            "sarif" => SarifWriter.Write(report, Version),
            null or "table" => TableWriter.Write(report),
            var other => throw new ArgumentException($"unknown format '{other}' (use table, json or sarif)"),
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

        foreach (var failed in report.Engines.Where(e => !e.Succeeded))
        {
            Console.Error.WriteLine($"warning: {failed.Engine} failed: {failed.Error}");
        }

        var failOn = options.Value("fail-on") ?? "high";
        if (failOn.Equals("none", StringComparison.OrdinalIgnoreCase))
        {
            return ExitPassed;
        }

        var gate = new QualityGate(Enum.Parse<Severity>(failOn, ignoreCase: true)).Evaluate(report.Findings);
        Console.Error.WriteLine(gate.Passed
            ? $"Quality gate passed (fail-on {failOn})."
            : $"Quality gate FAILED: {gate.Blocking.Count} finding(s) at {failOn} or above.");
        return gate.Passed ? ExitPassed : ExitGateFailed;
    }

    /// <summary>AI pen-test review: judge whether each finding is actually exploitable in this codebase.</summary>
    private static async Task<ScanReport> ReviewWithAiAsync(
        ScanReport report, string provider, Options options, IProgress<string> progress, CancellationToken cancellationToken)
    {
        using var http = new HttpClient { Timeout = TimeSpan.FromMinutes(10) };
        var model = options.Value("ai-model");
        ILlmClient llm = provider.ToLowerInvariant() switch
        {
            "claude" => new ClaudeLlmClient(model),
            "ollama" => new OllamaLlmClient(http, model ?? OllamaLlmClient.DefaultModel),
            _ => throw new ArgumentException($"unknown AI provider '{provider}' (use claude or ollama)"),
        };

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

    private static async Task<int> UpdateAsync(Options options)
    {
        var keyPath = options.Value("key") ?? Environment.GetEnvironmentVariable("BULWARK_TRUSTED_KEY");
        var publicKey = keyPath is not null ? await File.ReadAllTextAsync(keyPath) : TrustedKeys.Project;
        if (publicKey is null)
        {
            Console.Error.WriteLine("error: no trusted public key. Pass --key <public.pem> or set BULWARK_TRUSTED_KEY.");
            return ExitError;
        }

        var store = ManifestStore.Default();
        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(60) };
        http.DefaultRequestHeaders.UserAgent.ParseAdd($"bulwark/{Version}");
        var updater = new ManifestUpdater(http, store, publicKey);

        UpdateResult result;
        if (options.Value("from-file") is { } file)
        {
            var signature = await File.ReadAllTextAsync(options.Value("signature") ?? file + ".sig");
            result = updater.Install(await File.ReadAllBytesAsync(file), signature);
        }
        else
        {
            var url = options.Value("url") ?? Environment.GetEnvironmentVariable("BULWARK_MANIFEST_URL") ?? TrustedKeys.DefaultManifestUrl;
            if (url is null)
            {
                Console.Error.WriteLine("error: no manifest URL. Pass --url or set BULWARK_MANIFEST_URL.");
                return ExitError;
            }

            result = await updater.UpdateAsync(new Uri(url), CancellationToken.None);
        }

        Console.WriteLine(result.Message);
        return result.Status == UpdateStatus.Rejected ? ExitError : ExitPassed;
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
                var privatePath = Path.Combine(directory, "bulwark-signing.key");
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

                File.WriteAllText(Path.Combine(directory, "bulwark-signing.pub"), publicKey);
                Console.WriteLine($"Wrote {privatePath} (keep secret) and bulwark-signing.pub");
                return ExitPassed;
            }

            case "sign":
            {
                var manifestPath = options.Positional.ElementAtOrDefault(1) ?? throw new ArgumentException("usage: bulwark manifest sign <manifest.json> --private-key <key>");
                var keyPath = options.Value("private-key") ?? throw new ArgumentException("--private-key is required");
                var bytes = File.ReadAllBytes(manifestPath);
                EngineManifest.Parse(bytes); // Refuse to sign something the client could not read.
                File.WriteAllText(manifestPath + ".sig", ManifestSignature.Sign(bytes, File.ReadAllText(keyPath)));
                Console.WriteLine($"Wrote {manifestPath}.sig");
                return ExitPassed;
            }

            default:
                Console.Error.WriteLine("usage: bulwark manifest keygen [dir] | bulwark manifest sign <manifest.json> --private-key <key>");
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
            bulwark {Version} - open-source SCA, license and security scanning

            usage:
              bulwark scan [path] [--format table|json|sarif] [--output file]
                                  [--fail-on critical|high|medium|low|none] [--engines a,b] [--container]
                                  [--rules dir1,dir2]   extra Opengrep rule folders
                                  [--history full|off|<range>]  secrets in git history (default full;
                                                        e.g. origin/main..HEAD for just a PR's commits)
                                  [--ai claude|ollama] [--ai-model name] [--ai-min-severity medium] [--ai-max 25]
              bulwark engines [--container]        show pinned engines and how each will run
              bulwark update [--url url | --from-file manifest.json] [--key public.pem]
              bulwark manifest keygen [dir]        (maintainers) create a signing key pair
              bulwark manifest sign <file> --private-key <key>
              bulwark version

            exit codes: 0 passed, 1 quality gate failed, 2 error
            """);
        return ExitPassed;
    }
}

/// <summary>
/// Release-time constants. Both are null until the project publishes its first signed manifest;
/// set them in the release build so `bulwark update` works with no flags.
/// </summary>
internal static class TrustedKeys
{
    public const string? Project = null;
    public const string? DefaultManifestUrl = null;
}
