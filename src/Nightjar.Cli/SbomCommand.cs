using Nightjar.Core.Engines;
using Nightjar.Core.Sbom;
using Nightjar.Core.Updates;

namespace Nightjar.Cli;

/// <summary>
/// nightjar sbom [path] [--format cyclonedx|spdx] [--vex] [--output file]
/// --vex adds CycloneDX vulnerability statements derived from triage decisions
/// (false positive → false_positive, accepted risk → exploitable/will_not_fix, fixed → resolved).
/// </summary>
internal static class SbomCommand
{
    public static async Task<int> RunAsync(Options options)
    {
        var path = options.Positional.ElementAtOrDefault(0) ?? ".";
        if (!Directory.Exists(path))
        {
            Console.Error.WriteLine($"error: directory not found: {path}");
            return Cli.ExitError;
        }

        var format = (options.Value("format") ?? "cyclonedx").ToLowerInvariant();
        if (format is not ("cyclonedx" or "spdx") || (format == "spdx" && options.Has("vex")))
        {
            Console.Error.WriteLine("error: --format must be cyclonedx or spdx (--vex is CycloneDX only).");
            return Cli.ExitError;
        }

        var store = ManifestStore.Default();
        var (manifest, _) = store.Load();
        var wanted = options.Has("vex") ? new[] { "syft", "osv-scanner" } : ["syft"];
        var engines = EngineFactory.Create(EngineFactory.Runner(manifest, options), options)
            .Where(e => wanted.Contains(e.Name, StringComparer.OrdinalIgnoreCase)).ToArray();

        var pipeline = new ScanPipeline(engines, manifest);
        var report = await pipeline.RunAsync(path, new Progress<string>(m => Console.Error.WriteLine($"» {m}")), CancellationToken.None);
        if (pipeline.Sbom is not { } sbom)
        {
            Console.Error.WriteLine("error: no SBOM produced (is there a supported manifest in this project?).");
            return Cli.ExitError;
        }

        report = TriageCommand.AfterScan(report, options, store.HomeDirectory).Report;
        var output = format == "spdx"
            ? SbomExporter.Spdx(sbom, new DirectoryInfo(Path.GetFullPath(path)).Name, DateTimeOffset.UtcNow)
            : options.Has("vex") ? SbomExporter.CycloneDxWithVex(sbom, report.Findings) : sbom.CycloneDxJson;

        if (options.Value("output") is { } file)
        {
            await File.WriteAllTextAsync(file, output);
            Console.Error.WriteLine($"Wrote {format} SBOM ({sbom.Components.Count} components) to {file}");
        }
        else
        {
            Console.WriteLine(output);
        }

        return Cli.ExitPassed;
    }
}
