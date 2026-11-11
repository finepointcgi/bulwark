using System.Diagnostics;
using Bulwark.Core.Engines;
using Bulwark.Core.Policy;
using Bulwark.Engines.Execution;

namespace Bulwark.Engines.Syft;

/// <summary>
/// Builds the SBOM (CycloneDX) with Syft, publishes it to the scan context for later engines,
/// and runs the license policy over it.
/// </summary>
public sealed class SyftEngine(ToolRunner runner, LicensePolicy licensePolicy) : IEngine
{
    public string Name => "syft";
    public int Order => 10;

    public bool AppliesTo(ScanContext context) => context.Profile.HasDependencies || context.Profile.HasContainers;

    public async Task<EngineResult> RunAsync(ScanContext context, CancellationToken cancellationToken)
    {
        var stopwatch = Stopwatch.StartNew();
        const string sbomFile = "sbom.cdx.json";

        var output = await runner.RunAsync(
            Name,
            ["scan", $"dir:{ToolRunner.SourceToken}", "-o", $"cyclonedx-json={ToolRunner.WorkToken}/{sbomFile}", "-q"],
            context.RootPath, context.WorkDirectory, TimeSpan.FromMinutes(10), cancellationToken);

        var sbomPath = Path.Combine(context.WorkDirectory, sbomFile);
        if (output.ExitCode != 0 || !File.Exists(sbomPath))
        {
            return EngineResult.Failed(Name, $"syft exited {output.ExitCode}: {output.StandardError.Trim()}", stopwatch.Elapsed);
        }

        var json = await File.ReadAllTextAsync(sbomPath, cancellationToken);
        context.Sbom = CycloneDxParser.Parse(json, context.RootPath);

        var findings = licensePolicy.Evaluate(context.Sbom).Select(f => f with { Engines = [Name, .. f.Engines] }).ToList();
        return new EngineResult(Name, findings, stopwatch.Elapsed);
    }
}
