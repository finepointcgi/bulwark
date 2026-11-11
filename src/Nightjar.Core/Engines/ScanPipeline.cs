using System.Diagnostics;
using Nightjar.Core.Findings;
using Nightjar.Core.Reports;
using Nightjar.Core.Updates;

namespace Nightjar.Core.Engines;

/// <summary>
/// Runs every applicable engine, isolates failures (one broken engine never kills the scan),
/// and merges results into one deduplicated report.
/// </summary>
public sealed class ScanPipeline(IEnumerable<IEngine> engines, EngineManifest manifest)
{
    /// <summary>The SBOM produced during the last run, if an SBOM engine ran. Saved for continuous monitoring.</summary>
    public Sbom.SoftwareBillOfMaterials? Sbom { get; private set; }

    public async Task<ScanReport> RunAsync(string rootPath, IProgress<string>? progress, CancellationToken cancellationToken)
    {
        var started = DateTimeOffset.UtcNow;
        var stopwatch = Stopwatch.StartNew();
        var root = Path.GetFullPath(rootPath);
        var work = Directory.CreateTempSubdirectory("nightjar-").FullName;

        try
        {
            var context = new ScanContext { RootPath = root, WorkDirectory = work, Profile = ProjectDetector.Detect(root) };
            progress?.Report($"Detected: {Describe(context.Profile)}");

            var runs = new List<EngineRun>();
            var findings = new List<Finding>();

            foreach (var engine in engines.OrderBy(e => e.Order))
            {
                if (!engine.AppliesTo(context))
                {
                    continue;
                }

                progress?.Report($"Running {engine.Name}...");
                var version = manifest.Find(engine.ManifestName)?.Version ?? "built-in";
                EngineResult result;
                try
                {
                    result = await engine.RunAsync(context, cancellationToken);
                }
                catch (Exception e) when (e is not OperationCanceledException)
                {
                    result = EngineResult.Failed(engine.Name, e.Message, TimeSpan.Zero);
                }

                runs.Add(new EngineRun(engine.Name, version, result.Succeeded, result.Duration.TotalSeconds, result.Error));
                findings.AddRange(result.Findings);
            }

            Sbom = context.Sbom;
            return new ScanReport
            {
                Project = root,
                StartedAt = started,
                Seconds = stopwatch.Elapsed.TotalSeconds,
                ManifestSequence = manifest.Sequence,
                Engines = runs,
                Findings = Dependencies.ReachabilityAnalyzer.Annotate(root, FindingMerger.Merge(findings)),
                Metrics = context.Metrics.Count > 0 ? new Dictionary<string, double>(context.Metrics) : null,
            };
        }
        finally
        {
            try { Directory.Delete(work, recursive: true); } catch (IOException) { }
        }
    }

    private static string Describe(ProjectProfile profile)
    {
        var parts = new List<string>();
        if (profile.Ecosystems.Count > 0) { parts.Add($"ecosystems [{string.Join(", ", profile.Ecosystems.Order())}]"); }
        if (profile.Languages.Count > 0) { parts.Add($"languages [{string.Join(", ", profile.Languages.Order())}]"); }
        if (profile.HasContainers) { parts.Add("containers"); }
        if (profile.HasInfrastructureAsCode) { parts.Add("infrastructure-as-code"); }
        return parts.Count == 0 ? "nothing scannable" : string.Join("; ", parts);
    }
}
