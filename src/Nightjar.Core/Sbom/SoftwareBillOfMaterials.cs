using Nightjar.Core.Findings;

namespace Nightjar.Core.Sbom;

public sealed record SbomComponent(PackageRef Package, IReadOnlyList<string> Licenses, IReadOnlyList<string> FoundIn);

/// <summary>
/// Minimal in-memory SBOM. The raw CycloneDX document is kept as well so it can be exported
/// unchanged and re-checked against new advisories without rescanning the code.
/// </summary>
public sealed record SoftwareBillOfMaterials(IReadOnlyList<SbomComponent> Components, string CycloneDxJson);
