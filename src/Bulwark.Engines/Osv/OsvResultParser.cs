using System.Globalization;
using System.Text.Json;
using Bulwark.Core.Findings;
using Bulwark.Engines.Execution;

namespace Bulwark.Engines.Osv;

/// <summary>Maps OSV-Scanner JSON output to normalized findings.</summary>
public static class OsvResultParser
{
    public static IReadOnlyList<Finding> Parse(string json, string sourcePath, string engine)
    {
        using var document = JsonDocument.Parse(json);
        var findings = new List<Finding>();
        if (!document.RootElement.TryGetProperty("results", out var results))
        {
            return findings;
        }

        foreach (var result in results.EnumerateArray())
        {
            var sourceFile = result.TryGetProperty("source", out var source) && Str(source, "path") is { } p
                ? ToolRunner.ToProjectPath(p, sourcePath)
                : null;

            if (!result.TryGetProperty("packages", out var packages))
            {
                continue;
            }

            foreach (var entry in packages.EnumerateArray())
            {
                var pkg = entry.GetProperty("package");
                var package = new PackageRef(Str(pkg, "name") ?? "", Str(pkg, "version") ?? "", Str(pkg, "ecosystem") ?? "");
                var groupSeverity = GroupSeverities(entry);

                if (!entry.TryGetProperty("vulnerabilities", out var vulnerabilities))
                {
                    continue;
                }

                foreach (var vulnerability in vulnerabilities.EnumerateArray())
                {
                    var id = Str(vulnerability, "id") ?? "UNKNOWN";
                    var aliases = Strings(vulnerability, "aliases");
                    var severity = groupSeverity.GetValueOrDefault(id, Severity.Unknown);
                    if (severity == Severity.Unknown)
                    {
                        severity = DatabaseSeverity(vulnerability);
                    }

                    findings.Add(new Finding
                    {
                        Id = Fingerprint.ForVulnerability(package, id, aliases),
                        Category = FindingCategory.Vulnerability,
                        Severity = severity,
                        RuleId = id,
                        Title = $"{Str(vulnerability, "summary") ?? id} in {package.Name}@{package.Version}",
                        Description = Str(vulnerability, "details"),
                        Package = package,
                        Location = sourceFile is null ? null : new SourceLocation(sourceFile),
                        Aliases = aliases,
                        FixedVersions = FixedVersions(vulnerability, package),
                        References = References(vulnerability),
                        Engines = [engine],
                    });
                }
            }
        }

        return findings;
    }

    /// <summary>OSV-Scanner groups aliases together and gives each group a max CVSS score.</summary>
    private static Dictionary<string, Severity> GroupSeverities(JsonElement entry)
    {
        var map = new Dictionary<string, Severity>(StringComparer.OrdinalIgnoreCase);
        if (!entry.TryGetProperty("groups", out var groups))
        {
            return map;
        }

        foreach (var group in groups.EnumerateArray())
        {
            var severity = Str(group, "max_severity") is { } score
                && double.TryParse(score, NumberStyles.Float, CultureInfo.InvariantCulture, out var cvss)
                ? FromCvss(cvss)
                : Severity.Unknown;

            foreach (var id in Strings(group, "ids"))
            {
                map[id] = severity;
            }
        }

        return map;
    }

    public static Severity FromCvss(double score) => score switch
    {
        >= 9.0 => Severity.Critical,
        >= 7.0 => Severity.High,
        >= 4.0 => Severity.Medium,
        > 0 => Severity.Low,
        _ => Severity.Unknown,
    };

    private static Severity DatabaseSeverity(JsonElement vulnerability) =>
        vulnerability.TryGetProperty("database_specific", out var db) && Str(db, "severity") is { } text
            ? text.ToUpperInvariant() switch
            {
                "CRITICAL" => Severity.Critical,
                "HIGH" => Severity.High,
                "MODERATE" or "MEDIUM" => Severity.Medium,
                "LOW" => Severity.Low,
                _ => Severity.Unknown,
            }
            : Severity.Unknown;

    private static List<string> FixedVersions(JsonElement vulnerability, PackageRef package)
    {
        var fixes = new List<string>();
        if (!vulnerability.TryGetProperty("affected", out var affected))
        {
            return fixes;
        }

        foreach (var item in affected.EnumerateArray())
        {
            if (item.TryGetProperty("package", out var pkg)
                && !string.Equals(Str(pkg, "name"), package.Name, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (!item.TryGetProperty("ranges", out var ranges))
            {
                continue;
            }

            foreach (var range in ranges.EnumerateArray())
            {
                if (!range.TryGetProperty("events", out var events))
                {
                    continue;
                }

                foreach (var e in events.EnumerateArray())
                {
                    if (Str(e, "fixed") is { } fixedVersion)
                    {
                        fixes.Add(fixedVersion);
                    }
                }
            }
        }

        return fixes.Distinct().ToList();
    }

    private static List<string> References(JsonElement vulnerability) =>
        vulnerability.TryGetProperty("references", out var refs) && refs.ValueKind == JsonValueKind.Array
            ? refs.EnumerateArray().Select(r => Str(r, "url")).OfType<string>().ToList()
            : [];

    private static List<string> Strings(JsonElement element, string property) =>
        element.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.Array
            ? value.EnumerateArray().Where(v => v.ValueKind == JsonValueKind.String).Select(v => v.GetString()!).ToList()
            : [];

    private static string? Str(JsonElement element, string property) =>
        element.ValueKind == JsonValueKind.Object && element.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;
}
