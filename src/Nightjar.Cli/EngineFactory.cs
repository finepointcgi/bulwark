using Nightjar.Core.Engines;
using Nightjar.Core.Policy;
using Nightjar.Engines.Cppcheck;
using Nightjar.Engines.Execution;
using Nightjar.Engines.Gitleaks;
using Nightjar.Engines.Lizard;
using Nightjar.Engines.Opengrep;
using Nightjar.Engines.Osv;
using Nightjar.Engines.Syft;
using Nightjar.Engines.Trivy;

namespace Nightjar.Cli;

/// <summary>The static-analysis engine set, shared by `scan` and `canary` so they can never drift apart.</summary>
internal static class EngineFactory
{
    public static IEngine[] Create(ToolRunner runner, Options options)
    {
        var ruleDirectories = options.Value("rules")?.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries) ?? [];
        if (ruleDirectories.FirstOrDefault(d => !Directory.Exists(d)) is { } missing)
        {
            throw new ArgumentException($"rules directory not found: {missing}");
        }

        var images = options.Value("image")?.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries) ?? [];

        IEngine[] engines =
        [
            new SyftEngine(runner, new LicensePolicy()),
            new OsvScannerEngine(runner),
            new GitleaksEngine(runner, HistoryScope.Parse(options.Value("history"))),
            new OpengrepEngine(runner, ruleDirectories),
            new CppcheckEngine(runner),
            new TrivyIacEngine(runner),
            new TrivyImageEngine(runner, images, options.Has("image-include-unfixed")),
            new LizardEngine(runner, int.Parse(options.Value("max-complexity") ?? "15", System.Globalization.CultureInfo.InvariantCulture)),
            new CoverageEngine(),
        ];

        var only = options.Value("engines")?.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
        return only is null ? engines : engines.Where(e => only.Contains(e.Name, StringComparer.OrdinalIgnoreCase)).ToArray();
    }

    public static ToolRunner Runner(Nightjar.Core.Updates.EngineManifest manifest, Options options) =>
        new(manifest, options.Has("container") ? ToolMode.Container : ToolMode.Auto,
            Path.Combine(Nightjar.Core.Updates.ManifestStore.Default().HomeDirectory, "cache"));
}
