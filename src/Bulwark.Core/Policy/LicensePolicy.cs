using Bulwark.Core.Findings;
using Bulwark.Core.Sbom;

namespace Bulwark.Core.Policy;

/// <summary>
/// Turns SBOM licenses into findings. Defaults flag strong copyleft and unknown licenses,
/// which is what most companies' legal teams ask for first. Fully overridable in config.
/// </summary>
public sealed class LicensePolicy
{
    public IReadOnlySet<string> Denied { get; init; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "AGPL-1.0", "AGPL-3.0", "AGPL-3.0-only", "AGPL-3.0-or-later",
        "SSPL-1.0", "BUSL-1.1", "CC-BY-NC-4.0",
    };

    public IReadOnlySet<string> Review { get; init; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "GPL-2.0", "GPL-2.0-only", "GPL-2.0-or-later", "GPL-3.0", "GPL-3.0-only", "GPL-3.0-or-later",
        "LGPL-2.1", "LGPL-2.1-only", "LGPL-2.1-or-later", "LGPL-3.0", "LGPL-3.0-only", "LGPL-3.0-or-later",
        "MPL-2.0", "EPL-2.0", "CDDL-1.0",
    };

    public bool FlagUnknown { get; init; } = true;

    public IEnumerable<Finding> Evaluate(SoftwareBillOfMaterials sbom)
    {
        foreach (var component in sbom.Components)
        {
            if (component.Licenses.Count == 0)
            {
                if (FlagUnknown)
                {
                    yield return Create(component, "UNKNOWN", Severity.Low, "No license detected",
                        "No license could be determined for this package. Check it manually before shipping.");
                }

                continue;
            }

            foreach (var license in component.Licenses)
            {
                if (Denied.Contains(license))
                {
                    yield return Create(component, license, Severity.High, $"Denied license {license}",
                        $"{license} is on the deny list for this project.");
                }
                else if (Review.Contains(license))
                {
                    yield return Create(component, license, Severity.Medium, $"License needs review: {license}",
                        $"{license} has obligations that depend on how the package is used and distributed.");
                }
            }
        }
    }

    private static Finding Create(SbomComponent component, string license, Severity severity, string title, string description) => new()
    {
        Id = Fingerprint.ForLicense(component.Package, license),
        Category = FindingCategory.License,
        Severity = severity,
        RuleId = $"license/{license}",
        Title = $"{title} in {component.Package.Name}@{component.Package.Version}",
        Description = description,
        Package = component.Package,
        Location = component.FoundIn.Count > 0 ? new SourceLocation(component.FoundIn[0]) : null,
        Engines = ["license-policy"],
    };
}
