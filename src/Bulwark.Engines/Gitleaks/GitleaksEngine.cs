using System.Diagnostics;
using Bulwark.Core.Engines;
using Bulwark.Engines.Execution;

namespace Bulwark.Engines.Gitleaks;

/// <summary>
/// Hard-coded secrets (API keys, tokens, private keys) with gitleaks. Scans the working tree;
/// the raw report contains the secrets, so it is parsed and deleted immediately and only a
/// hash and a masked preview are kept.
/// </summary>
public sealed class GitleaksEngine(ToolRunner runner) : IEngine
{
    public string Name => "gitleaks";
    public int Order => 30;

    public bool AppliesTo(ScanContext context) => true;

    public async Task<EngineResult> RunAsync(ScanContext context, CancellationToken cancellationToken)
    {
        var stopwatch = Stopwatch.StartNew();
        const string reportFile = "gitleaks.json";
        var reportPath = Path.Combine(context.WorkDirectory, reportFile);

        try
        {
            var output = await runner.RunAsync(
                Name,
                ["dir", ToolRunner.SourceToken, "--report-format", "json", "--report-path", $"{ToolRunner.WorkToken}/{reportFile}",
                    "--exit-code", "0", "--no-banner", "--log-level", "error"],
                context.RootPath, context.WorkDirectory, TimeSpan.FromMinutes(10), cancellationToken);

            if (output.ExitCode != 0 || !File.Exists(reportPath))
            {
                return EngineResult.Failed(Name, $"gitleaks exited {output.ExitCode}: {output.StandardError.Trim()}", stopwatch.Elapsed);
            }

            var findings = GitleaksParser.Parse(await File.ReadAllTextAsync(reportPath, cancellationToken), context.RootPath, Name);
            return new EngineResult(Name, findings, stopwatch.Elapsed);
        }
        finally
        {
            File.Delete(reportPath);
        }
    }
}
