using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Nodes;
using Nightjar.Core.Findings;
using Nightjar.Core.Reports;
using Nightjar.Core.Sbom;

namespace Nightjar.Core.Monitoring;

public sealed record MonitorResult(string Project, int PackagesChecked, IReadOnlyList<Finding> NewFindings);

/// <summary>
/// Re-checks saved SBOMs against OSV.dev without rescanning code: a CVE published today for a
/// dependency you shipped last month shows up within a day. New advisories are added to the
/// project's saved report (so the dashboard shows them) and returned for alerting.
/// Only package URLs (name + version) are sent to OSV, the same data OSV-Scanner sends.
/// </summary>
public sealed class AdvisoryMonitor(HttpClient http, ReportArchive archive)
{
    private const string Api = "https://api.osv.dev/v1";
    private const int BatchSize = 500;

    public async Task<IReadOnlyList<MonitorResult>> CheckAllAsync(string? onlyProject, CancellationToken cancellationToken)
    {
        var results = new List<MonitorResult>();
        foreach (var report in archive.LoadAll())
        {
            if (onlyProject is not null && report.Project != onlyProject)
            {
                continue;
            }

            var sbomPath = archive.SbomPath(report.Project);
            if (!File.Exists(sbomPath))
            {
                continue;
            }

            var sbom = SbomReader.Read(await File.ReadAllTextAsync(sbomPath, cancellationToken));
            var fresh = await CheckAsync(report, sbom, cancellationToken);
            if (fresh.Count > 0)
            {
                archive.Save(report with { Findings = FindingMerger.Merge(report.Findings.Concat(fresh)) });
            }

            results.Add(new MonitorResult(report.Project, sbom.Count, fresh));
        }

        return results;
    }

    /// <summary>Advisories affecting the SBOM that the report does not already contain.</summary>
    public async Task<IReadOnlyList<Finding>> CheckAsync(ScanReport report, IReadOnlyList<SbomComponent> components, CancellationToken cancellationToken)
    {
        var known = report.Findings.Select(f => f.Id).ToHashSet(StringComparer.Ordinal);
        var knownAdvisories = report.Findings
            .Where(f => f.Package is not null)
            .SelectMany(f => f.Aliases.Append(f.RuleId).Select(a => (f.Package!.Name, f.Package.Version, a.ToUpperInvariant())))
            .ToHashSet();

        var withPurl = components.Where(c => c.Package.Purl is not null).ToList();
        var hits = new List<(SbomComponent Component, string VulnId)>();
        foreach (var batch in withPurl.Chunk(BatchSize))
        {
            var body = new JsonObject
            {
                ["queries"] = new JsonArray(batch.Select(c => (JsonNode)new JsonObject
                {
                    ["package"] = new JsonObject { ["purl"] = c.Package.Purl },
                }).ToArray()),
            };

            using var response = await http.PostAsJsonAsync($"{Api}/querybatch", body, cancellationToken);
            response.EnsureSuccessStatusCode();
            var json = await response.Content.ReadFromJsonAsync<JsonObject>(cancellationToken);
            var results = json?["results"]?.AsArray() ?? [];
            for (var i = 0; i < results.Count && i < batch.Length; i++)
            {
                foreach (var vuln in results[i]?["vulns"]?.AsArray() ?? [])
                {
                    if (vuln?["id"]?.GetValue<string>() is { } id)
                    {
                        hits.Add((batch[i], id));
                    }
                }
            }
        }

        var findings = new List<Finding>();
        var details = new Dictionary<string, JsonObject?>(StringComparer.Ordinal);
        foreach (var (component, id) in hits)
        {
            if (knownAdvisories.Contains((component.Package.Name, component.Package.Version, id.ToUpperInvariant())))
            {
                continue;
            }

            if (!details.TryGetValue(id, out var vuln))
            {
                vuln = details[id] = await http.GetFromJsonAsync<JsonObject>($"{Api}/vulns/{Uri.EscapeDataString(id)}", cancellationToken);
            }

            if (vuln is null)
            {
                continue;
            }

            var finding = ToFinding(component, id, vuln);
            if (!known.Contains(finding.Id))
            {
                findings.Add(finding);
            }
        }

        return FindingMerger.Merge(findings);
    }

    internal static Finding ToFinding(SbomComponent component, string id, JsonObject vuln)
    {
        var aliases = vuln["aliases"]?.AsArray().Select(a => a?.GetValue<string>()).OfType<string>().ToList() ?? [];
        var package = component.Package;
        return new Finding
        {
            Id = Fingerprint.ForVulnerability(package, id, aliases),
            Category = FindingCategory.Vulnerability,
            Severity = Severity(vuln),
            RuleId = id,
            Title = $"{vuln["summary"]?.GetValue<string>() ?? id} in {package.Name}@{package.Version}",
            Description = vuln["details"]?.GetValue<string>(),
            Package = package,
            Location = component.FoundIn.Count > 0 ? new SourceLocation(component.FoundIn[0]) : null,
            Aliases = aliases,
            FixedVersions = FixedVersions(vuln, package.Name),
            References = vuln["references"]?.AsArray().Select(r => r?["url"]?.GetValue<string>()).OfType<string>().ToList() ?? [],
            Engines = ["osv-monitor"],
        };
    }

    private static Severity Severity(JsonObject vuln) =>
        (vuln["database_specific"]?["severity"]?.GetValue<string>() ?? "").ToUpperInvariant() switch
        {
            "CRITICAL" => Findings.Severity.Critical,
            "HIGH" => Findings.Severity.High,
            "MODERATE" or "MEDIUM" => Findings.Severity.Medium,
            "LOW" => Findings.Severity.Low,
            _ => Findings.Severity.Unknown,
        };

    private static List<string> FixedVersions(JsonObject vuln, string packageName) =>
        (vuln["affected"]?.AsArray() ?? [])
            .Where(a => string.Equals(a?["package"]?["name"]?.GetValue<string>(), packageName, StringComparison.OrdinalIgnoreCase))
            .SelectMany(a => a?["ranges"]?.AsArray() ?? [])
            .SelectMany(r => r?["events"]?.AsArray() ?? [])
            .Select(e => e?["fixed"]?.GetValue<string>())
            .OfType<string>()
            .Distinct()
            .ToList();
}

/// <summary>Reads components back from a saved CycloneDX SBOM (the subset Nightjar wrote).</summary>
public static class SbomReader
{
    public static IReadOnlyList<SbomComponent> Read(string cycloneDxJson)
    {
        using var document = JsonDocument.Parse(cycloneDxJson);
        var list = new List<SbomComponent>();
        if (!document.RootElement.TryGetProperty("components", out var components))
        {
            return list;
        }

        foreach (var c in components.EnumerateArray())
        {
            if (Str(c, "purl") is not { } purl || Str(c, "name") is not { } name)
            {
                continue;
            }

            var type = purl.StartsWith("pkg:", StringComparison.Ordinal) ? purl[4..].Split('/')[0] : "";
            var ecosystem = type switch
            {
                "npm" => "npm", "pypi" => "PyPI", "golang" => "Go", "cargo" => "crates.io", "maven" => "Maven",
                "nuget" => "NuGet", "gem" => "RubyGems", "composer" => "Packagist", "pub" => "Pub", _ => type,
            };

            var foundIn = new List<string>();
            if (c.TryGetProperty("properties", out var properties))
            {
                foundIn.AddRange(properties.EnumerateArray()
                    .Where(p => Str(p, "name") is { } n && n.StartsWith("syft:location:", StringComparison.Ordinal) && n.EndsWith(":path", StringComparison.Ordinal))
                    .Select(p => Str(p, "value")!.TrimStart('/')));
            }

            list.Add(new SbomComponent(new PackageRef(name, Str(c, "version") ?? "", ecosystem, purl), [], foundIn));
        }

        return list;
    }

    private static string? Str(JsonElement e, string p) =>
        e.ValueKind == JsonValueKind.Object && e.TryGetProperty(p, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
}
