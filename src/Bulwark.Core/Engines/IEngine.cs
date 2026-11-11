using Bulwark.Core.Findings;
using Bulwark.Core.Sbom;

namespace Bulwark.Core.Engines;

/// <summary>
/// One scanner engine (Syft, OSV-Scanner, Opengrep, gitleaks, ...).
/// Adapters stay small: decide whether they apply, run the tool, map its output.
/// Adding an engine should never require changes outside its adapter.
/// </summary>
public interface IEngine
{
    /// <summary>Short id that matches the engine's entry in the signed manifest.</summary>
    string Name { get; }

    /// <summary>Engines with lower order run first; SBOM producers run before SBOM consumers.</summary>
    int Order => 100;

    /// <summary>Cheap check: does this engine have anything to scan in this project?</summary>
    bool AppliesTo(ScanContext context);

    Task<EngineResult> RunAsync(ScanContext context, CancellationToken cancellationToken);
}

/// <summary>Shared state for one scan. Earlier engines can publish data (like the SBOM) for later ones.</summary>
public sealed class ScanContext
{
    public required string RootPath { get; init; }
    public required string WorkDirectory { get; init; }
    public required ProjectProfile Profile { get; init; }

    /// <summary>Set by the SBOM engine; read by license and vulnerability engines.</summary>
    public SoftwareBillOfMaterials? Sbom { get; set; }
}

public sealed record EngineResult(
    string Engine,
    IReadOnlyList<Finding> Findings,
    TimeSpan Duration,
    string? Error = null)
{
    public bool Succeeded => Error is null;

    public static EngineResult Failed(string engine, string error, TimeSpan duration) => new(engine, [], duration, error);
}
