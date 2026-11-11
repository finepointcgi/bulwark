using System.Diagnostics;
using Nightjar.Core.Engines;
using Nightjar.Engines.Execution;

namespace Nightjar.Engines.Osv;

/// <summary>Known-vulnerability scan of dependencies with OSV-Scanner (v2 CLI).</summary>
public sealed class OsvScannerEngine(ToolRunner runner) : IEngine
{
    public string Name => "osv-scanner";
    public int Order => 20;

    public bool AppliesTo(ScanContext context) => context.Profile.HasDependencies;

    public async Task<EngineResult> RunAsync(ScanContext context, CancellationToken cancellationToken)
    {
        var stopwatch = Stopwatch.StartNew();
        var output = await runner.RunAsync(
            Name,
            ["scan", "source", "--recursive", "--format", "json", ToolRunner.SourceToken],
            context.RootPath, context.WorkDirectory, TimeSpan.FromMinutes(10), cancellationToken);

        // 0 = clean, 1 = vulnerabilities found, 128 = no packages found. Anything else is a real error.
        if (output.ExitCode is not (0 or 1 or 128))
        {
            return EngineResult.Failed(Name, $"osv-scanner exited {output.ExitCode}: {output.StandardError.Trim()}", stopwatch.Elapsed);
        }

        if (output.ExitCode == 128 || string.IsNullOrWhiteSpace(output.StandardOutput))
        {
            return new EngineResult(Name, [], stopwatch.Elapsed);
        }

        var findings = OsvResultParser.Parse(output.StandardOutput, context.RootPath, Name);
        return new EngineResult(Name, findings, stopwatch.Elapsed);
    }
}
