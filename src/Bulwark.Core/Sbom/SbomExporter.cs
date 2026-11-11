using System.Text.Json;
using System.Text.Json.Nodes;
using Bulwark.Core.Findings;

namespace Bulwark.Core.Sbom;

/// <summary>
/// Turns the scan's SBOM into deliverables: CycloneDX (optionally with VEX statements built from
/// triage decisions) and SPDX 2.3 JSON.
/// </summary>
public static class SbomExporter
{
    private static readonly JsonSerializerOptions Pretty = new() { WriteIndented = true };

    /// <summary>VEX analysis state for a triage state, per CycloneDX 1.5 <c>analysis.state</c>.</summary>
    public static (string State, string? Response, string? Justification) VexFor(TriageState state, Reachability reachability) => state switch
    {
        TriageState.FalsePositive => ("false_positive", null, null),
        TriageState.AcceptedRisk => ("exploitable", "will_not_fix", null),
        TriageState.Fixed => ("resolved", "update", null),
        TriageState.Confirmed => ("exploitable", null, null),
        // Not imported is a hint, not a proof: leave it in triage rather than claiming "not_affected".
        _ => ("in_triage", null, null),
    };

    /// <summary>CycloneDX document with a <c>vulnerabilities</c> section (the VEX part) for every dependency finding.</summary>
    public static string CycloneDxWithVex(SoftwareBillOfMaterials sbom, IEnumerable<Finding> findings, string? reasonFor = null)
    {
        var root = JsonNode.Parse(sbom.CycloneDxJson)!.AsObject();
        root["specVersion"] ??= "1.5";
        var refs = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var component in (root["components"] as JsonArray ?? []).Select(c => c?.AsObject()).Where(c => c is not null))
        {
            var key = component!["purl"]?.GetValue<string>() ?? $"{component["name"]}@{component["version"]}";
            // The same package can appear several times (one per manifest); the first reference is enough.
            refs.TryAdd(key, component["bom-ref"]?.GetValue<string>() ?? component["purl"]?.GetValue<string>() ?? "");
        }

        var vulnerabilities = new JsonArray();
        foreach (var f in findings.Where(f => f.Category == FindingCategory.Vulnerability && f.Package is not null))
        {
            var (state, response, justification) = VexFor(f.Triage, f.Reachability);
            var analysis = new JsonObject { ["state"] = state };
            if (response is not null) { analysis["response"] = new JsonArray(response); }
            if (justification is not null) { analysis["justification"] = justification; }
            if (f.Reachability == Reachability.NotImported) { analysis["detail"] = "Not imported directly by first-party code (may still be reachable through another dependency)."; }

            var package = f.Package!;
            var key = package.Purl ?? $"{package.Name}@{package.Version}";
            var vulnerability = new JsonObject
            {
                ["id"] = f.RuleId,
                ["source"] = new JsonObject { ["name"] = f.RuleId.StartsWith("GHSA", StringComparison.OrdinalIgnoreCase) ? "GitHub" : "OSV" },
                ["ratings"] = new JsonArray(new JsonObject { ["severity"] = f.Severity.ToString().ToLowerInvariant() }),
                ["description"] = f.Title,
                ["analysis"] = analysis,
                ["affects"] = new JsonArray(new JsonObject { ["ref"] = refs.TryGetValue(key, out var r) && r.Length > 0 ? r : key }),
            };
            vulnerabilities.Add(vulnerability);
        }

        root["vulnerabilities"] = vulnerabilities;
        return root.ToJsonString(Pretty);
    }

    /// <summary>SPDX 2.3 JSON. Licenses that are not valid SPDX expressions are recorded as NOASSERTION.</summary>
    public static string Spdx(SoftwareBillOfMaterials sbom, string projectName, DateTimeOffset created)
    {
        var packages = new JsonArray();
        var relationships = new JsonArray();
        var index = 0;
        foreach (var c in sbom.Components)
        {
            var id = $"SPDXRef-Package-{++index}";
            var package = new JsonObject
            {
                ["SPDXID"] = id,
                ["name"] = c.Package.Name,
                ["versionInfo"] = c.Package.Version,
                ["downloadLocation"] = "NOASSERTION",
                ["filesAnalyzed"] = false,
                ["licenseConcluded"] = "NOASSERTION",
                ["licenseDeclared"] = c.Licenses.Count > 0 ? string.Join(" AND ", c.Licenses.Select(l => c.Licenses.Count > 1 && l.Contains(' ') ? $"({l})" : l)) : "NOASSERTION",
                ["copyrightText"] = "NOASSERTION",
            };
            if (c.Package.Purl is { } purl)
            {
                package["externalRefs"] = new JsonArray(new JsonObject { ["referenceCategory"] = "PACKAGE-MANAGER", ["referenceType"] = "purl", ["referenceLocator"] = purl });
            }

            packages.Add(package);
            relationships.Add(new JsonObject { ["spdxElementId"] = "SPDXRef-DOCUMENT", ["relationshipType"] = "DESCRIBES", ["relatedSpdxElement"] = id });
        }

        var document = new JsonObject
        {
            ["spdxVersion"] = "SPDX-2.3",
            ["dataLicense"] = "CC0-1.0",
            ["SPDXID"] = "SPDXRef-DOCUMENT",
            ["name"] = projectName,
            ["documentNamespace"] = $"https://bulwark.invalid/spdx/{Uri.EscapeDataString(projectName)}/{Guid.NewGuid()}",
            ["creationInfo"] = new JsonObject { ["created"] = created.UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ssZ"), ["creators"] = new JsonArray("Tool: Bulwark") },
            ["packages"] = packages,
            ["relationships"] = relationships,
        };
        return document.ToJsonString(Pretty);
    }
}
