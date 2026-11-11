using System.Diagnostics;
using Nightjar.Core.Engines;
using Nightjar.Engines.Execution;

namespace Nightjar.Engines.Gitleaks;

/// <summary>How much git history to scan for secrets.</summary>
public sealed record HistoryScope
{
    public static readonly HistoryScope Off = new() { Enabled = false };
    public static readonly HistoryScope Full = new() { Enabled = true };

    public bool Enabled { get; private init; }

    /// <summary>Optional <c>git log</c> options, e.g. <c>origin/main..HEAD</c> to scan only a PR's commits.</summary>
    public string? LogOptions { get; private init; }

    public static HistoryScope Range(string logOptions) => new() { Enabled = true, LogOptions = logOptions };

    /// <summary>Parses the CLI value: <c>off</c>, <c>full</c>, or anything else as git log options.</summary>
    public static HistoryScope Parse(string? value) => value?.Trim().ToLowerInvariant() switch
    {
        null or "" or "full" or "on" => Full,
        "off" or "none" or "false" => Off,
        _ => Range(value!.Trim()),
    };
}

/// <summary>
/// Hard-coded secrets (API keys, tokens, private keys) with gitleaks, in the working tree and,
/// when the project is a git repository, in its history. The raw reports contain the secrets,
/// so they are parsed and deleted immediately and only a hash and a masked preview are kept.
/// </summary>
public sealed class GitleaksEngine(ToolRunner runner, HistoryScope? history = null) : IEngine
{
    // Inside the container the repo is owned by another user, which git refuses by default.
    // Marking it safe is fine here: the mount is read-only and only `git log` runs.
    private static readonly Dictionary<string, string> GitEnvironment = new()
    {
        ["GIT_CONFIG_COUNT"] = "1",
        ["GIT_CONFIG_KEY_0"] = "safe.directory",
        ["GIT_CONFIG_VALUE_0"] = "*",
    };

    private readonly HistoryScope _history = history ?? HistoryScope.Full;

    public string Name => "gitleaks";
    public int Order => 30;

    public bool AppliesTo(ScanContext context) => true;

    /// <summary>History needs the repository root (a .git directory) at the scan root.</summary>
    public static bool IsGitRepository(string root) => Directory.Exists(Path.Combine(root, ".git"));

    public async Task<EngineResult> RunAsync(ScanContext context, CancellationToken cancellationToken)
    {
        var stopwatch = Stopwatch.StartNew();

        var (workingTreeJson, error) = await RunReportAsync(context, "gitleaks-dir.json", ["dir", ToolRunner.SourceToken], cancellationToken);
        if (error is not null)
        {
            return EngineResult.Failed(Name, error, stopwatch.Elapsed);
        }

        var findings = GitleaksParser.Parse(workingTreeJson!, context.RootPath, Name);

        if (_history.Enabled && IsGitRepository(context.RootPath))
        {
            string[] gitArguments = _history.LogOptions is { } logOptions
                ? ["git", ToolRunner.SourceToken, "--log-opts", logOptions]
                : ["git", ToolRunner.SourceToken];

            var (historyJson, historyError) = await RunReportAsync(context, "gitleaks-git.json", gitArguments, cancellationToken);
            if (historyError is not null)
            {
                // Keep the working-tree results; report the history failure so it is visible.
                return new EngineResult(Name, findings, stopwatch.Elapsed, $"history scan failed: {historyError}");
            }

            findings = GitleaksParser.Combine(findings, GitleaksParser.ParseLeaks(historyJson!, context.RootPath, Name));
        }

        return new EngineResult(Name, findings, stopwatch.Elapsed);
    }

    private async Task<(string? Json, string? Error)> RunReportAsync(
        ScanContext context, string reportFile, string[] mode, CancellationToken cancellationToken)
    {
        var reportPath = Path.Combine(context.WorkDirectory, reportFile);
        try
        {
            var output = await runner.RunAsync(
                Name,
                [.. mode, "--report-format", "json", "--report-path", $"{ToolRunner.WorkToken}/{reportFile}",
                    "--exit-code", "0", "--no-banner", "--log-level", "error"],
                context.RootPath, context.WorkDirectory, TimeSpan.FromMinutes(20), cancellationToken, GitEnvironment);

            if (output.ExitCode != 0 || !File.Exists(reportPath))
            {
                return (null, $"gitleaks {mode[0]} exited {output.ExitCode}: {output.StandardError.Trim()}");
            }

            return (await File.ReadAllTextAsync(reportPath, cancellationToken), null);
        }
        finally
        {
            File.Delete(reportPath);
        }
    }
}
