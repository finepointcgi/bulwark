using System.Diagnostics;
using Nightjar.Core.Dast;
using Nightjar.Core.Engines;
using Nightjar.Engines.Execution;

namespace Nightjar.Engines.Nuclei;

/// <summary>
/// nuclei with the tags and focus paths from the pentest plan. Only HTTP templates run, so every
/// request goes through the scope proxy; out-of-band (interactsh) callbacks, template updates and
/// destructive tags are switched off.
/// </summary>
public sealed class NucleiEngine(ToolRunner runner) : IDastEngine
{
    private const string TargetsFile = "targets.txt";
    private const string ResultsFile = "nuclei.jsonl";
    private const string SecretsFile = "secrets.yaml";

    public string Name => "nuclei";
    public int Order => 50;

    public async Task<EngineResult> RunAsync(DastContext context, CancellationToken cancellationToken)
    {
        var stopwatch = Stopwatch.StartNew();
        var work = Path.Combine(context.WorkDirectory, "nuclei");
        Directory.CreateDirectory(work);

        // Templates append their own paths ({{BaseURL}}/.env), so bases carry no trailing slash.
        var targets = new List<string> { context.Target.ToString().TrimEnd('/') };
        targets.AddRange(context.Plan.FocusPaths.Select(p => new Uri(context.Target, p).ToString().TrimEnd('/')));
        await File.WriteAllLinesAsync(Path.Combine(work, TargetsFile), targets.Distinct(), cancellationToken);

        var container = runner.IsContainer(Name);
        var arguments = BuildArguments(context, container);
        var secretsPath = Path.Combine(work, SecretsFile);
        if (context.Auth is { } auth)
        {
            await WriteSecretsFileAsync(secretsPath, context.Target, auth, cancellationToken);
            arguments.AddRange(["-sf", $"{ToolRunner.WorkToken}/{SecretsFile}"]);
        }

        var resultsPath = Path.Combine(work, ResultsFile);
        ToolOutput output;
        try
        {
            output = await runner.RunAsync(Name, arguments, work, work, context.Remaining, cancellationToken);
        }
        catch (TimeoutException)
        {
            // nuclei writes each result as it finds it, so a run cut off by the deadline still counts.
            var partial = File.Exists(resultsPath) ? await File.ReadAllLinesAsync(resultsPath, CancellationToken.None) : [];
            return new EngineResult(Name, NucleiParser.Parse(partial), stopwatch.Elapsed,
                $"stopped at the time budget; {partial.Length} result(s) kept. Raise timeBudgetMinutes or narrow the tags for a full run.");
        }
        finally
        {
            File.Delete(secretsPath);
        }

        if (output.ExitCode != 0 && !File.Exists(resultsPath))
        {
            var detail = string.Join(' ', output.StandardError.Split('\n').TakeLast(5)).Trim();
            return EngineResult.Failed(Name, $"exit {output.ExitCode}: {detail}", stopwatch.Elapsed);
        }

        var lines = File.Exists(resultsPath) ? await File.ReadAllLinesAsync(resultsPath, cancellationToken) : [];
        return new EngineResult(Name, NucleiParser.Parse(lines), stopwatch.Elapsed);
    }

    /// <summary>
    /// nuclei's static-auth secrets file: the header goes only to the target's host, never to any
    /// other host a template might reference. Readable only by the current user.
    /// </summary>
    internal static async Task WriteSecretsFileAsync(string path, Uri target, AuthHeader auth, CancellationToken cancellationToken)
    {
        // JSON strings are valid YAML scalars, which handles quoting of any header value.
        static string Quote(string value) => System.Text.Json.JsonSerializer.Serialize(value);
        var yaml = $"""
            static:
              - type: header
                domains:
                  - {Quote(target.Host)}
                  - {Quote(target.Authority)}
                headers:
                  - key: {Quote(auth.Name)}
                    value: {Quote(auth.Value)}

            """;
        await File.WriteAllTextAsync(path, yaml, cancellationToken);
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
    }

    internal static List<string> BuildArguments(DastContext context, bool container)
    {
        var arguments = new List<string>
        {
            "-l", $"{ToolRunner.WorkToken}/{TargetsFile}",
            "-jsonl", "-o", $"{ToolRunner.WorkToken}/{ResultsFile}",
            "-proxy", container ? context.ContainerProxyUrl : context.LocalProxyUrl,
            "-rl", context.Scope.MaxRequestsPerSecond.ToString(System.Globalization.CultureInfo.InvariantCulture),
            "-c", "5",
            "-timeout", "10",
            "-retries", "1",
            "-t", "http/",
            "-tags", string.Join(',', context.Plan.NucleiTags),
            "-etags", string.Join(',', PentestPlanner.ExcludedTags),
            "-ni",          // no interactsh: out-of-band callbacks would leave the scope
            "-duc",         // no update check
            "-silent", "-nc",
        };

        if (container)
        {
            // Pinned templates baked into the Nightjar image (engines/nuclei/Dockerfile).
            arguments.AddRange(["-ud", "/templates"]);
        }

        return arguments;
    }
}
