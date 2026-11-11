using System.Text.Json;
using Nightjar.Core.Findings;
using Nightjar.Core.Sbom;
using Nightjar.Engines.Execution;

namespace Nightjar.Engines.Syft;

/// <summary>Reads the parts of a CycloneDX JSON document Nightjar needs: packages, licenses, locations.</summary>
public static class CycloneDxParser
{
    private static readonly Dictionary<string, string> PurlEcosystems = new(StringComparer.OrdinalIgnoreCase)
    {
        ["npm"] = "npm", ["pypi"] = "PyPI", ["golang"] = "Go", ["cargo"] = "crates.io", ["maven"] = "Maven",
        ["nuget"] = "NuGet", ["gem"] = "RubyGems", ["composer"] = "Packagist", ["pub"] = "Pub",
        ["deb"] = "Debian", ["apk"] = "Alpine", ["rpm"] = "RPM", ["github"] = "GitHub Actions",
    };

    public static SoftwareBillOfMaterials Parse(string json, string sourcePath)
    {
        using var document = JsonDocument.Parse(json);
        var components = new List<SbomComponent>();

        if (document.RootElement.TryGetProperty("components", out var list) && list.ValueKind == JsonValueKind.Array)
        {
            foreach (var component in list.EnumerateArray())
            {
                var purl = GetString(component, "purl");
                var name = GetString(component, "name");
                if (purl is null || name is null)
                {
                    continue; // Files and other non-package components.
                }

                var package = new PackageRef(name, GetString(component, "version") ?? "", EcosystemFromPurl(purl), purl);
                components.Add(new SbomComponent(package, ReadLicenses(component), ReadLocations(component, sourcePath)));
            }
        }

        return new SoftwareBillOfMaterials(components, json);
    }

    public static string EcosystemFromPurl(string purl)
    {
        // pkg:<type>/<namespace>/<name>@<version>
        var type = purl.StartsWith("pkg:", StringComparison.OrdinalIgnoreCase) ? purl[4..].Split('/')[0] : "";
        return PurlEcosystems.GetValueOrDefault(type, type);
    }

    private static List<string> ReadLicenses(JsonElement component)
    {
        var licenses = new List<string>();
        if (!component.TryGetProperty("licenses", out var entries) || entries.ValueKind != JsonValueKind.Array)
        {
            return licenses;
        }

        foreach (var entry in entries.EnumerateArray())
        {
            if (GetString(entry, "expression") is { } expression)
            {
                // "MIT OR Apache-2.0" → each id, so policy can match any of them.
                licenses.AddRange(expression.Split([' ', '(', ')'], StringSplitOptions.RemoveEmptyEntries)
                    .Where(t => t is not ("AND" or "OR" or "WITH")));
            }
            else if (entry.TryGetProperty("license", out var license))
            {
                if ((GetString(license, "id") ?? GetString(license, "name")) is { } id)
                {
                    licenses.Add(id);
                }
            }
        }

        return licenses.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }

    private static List<string> ReadLocations(JsonElement component, string sourcePath)
    {
        var locations = new List<string>();
        if (!component.TryGetProperty("properties", out var properties) || properties.ValueKind != JsonValueKind.Array)
        {
            return locations;
        }

        foreach (var property in properties.EnumerateArray())
        {
            var name = GetString(property, "name");
            if (name is not null && name.StartsWith("syft:location:", StringComparison.Ordinal) && name.EndsWith(":path", StringComparison.Ordinal)
                && GetString(property, "value") is { } path)
            {
                // Syft reports paths relative to the scanned folder ("/src/app/package.json" means the
                // project's own src folder), so never strip a container mount prefix here.
                locations.Add(path.TrimStart('/'));
            }
        }

        return locations.Distinct().ToList();
    }

    private static string? GetString(JsonElement element, string property) =>
        element.ValueKind == JsonValueKind.Object && element.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;
}
