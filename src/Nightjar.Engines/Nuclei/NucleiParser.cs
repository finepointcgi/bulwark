using System.Text.Json;
using Nightjar.Core.Findings;

namespace Nightjar.Engines.Nuclei;

/// <summary>Maps nuclei JSON-lines output to findings.</summary>
public static class NucleiParser
{
    public static IReadOnlyList<Finding> Parse(IEnumerable<string> lines)
    {
        var findings = new List<Finding>();
        foreach (var line in lines.Where(l => l.TrimStart().StartsWith('{')))
        {
            JsonDocument document;
            try
            {
                document = JsonDocument.Parse(line);
            }
            catch (JsonException)
            {
                continue;
            }

            using (document)
            {
                var root = document.RootElement;
                var templateId = Text(root, "template-id") ?? "unknown";
                var matched = Text(root, "matched-at") ?? Text(root, "url") ?? Text(root, "host");
                if (matched is null || !Uri.TryCreate(matched, UriKind.Absolute, out var uri))
                {
                    continue;
                }

                root.TryGetProperty("info", out var info);
                var severity = (Text(info, "severity") ?? "").ToLowerInvariant() switch
                {
                    "critical" => Severity.Critical,
                    "high" => Severity.High,
                    "medium" => Severity.Medium,
                    "low" => Severity.Low,
                    "info" => Severity.Info,
                    _ => Severity.Unknown,
                };

                var aliases = new List<string>();
                if (info.ValueKind == JsonValueKind.Object && info.TryGetProperty("classification", out var classification))
                {
                    aliases.AddRange(Strings(classification, "cve-id").Select(s => s.ToUpperInvariant()));
                    aliases.AddRange(Strings(classification, "cwe-id").Select(s => s.ToUpperInvariant()));
                }

                var matcher = Text(root, "matcher-name");
                var extracted = Strings(root, "extracted-results").Take(3).ToList();

                findings.Add(new Finding
                {
                    Id = Fingerprint.ForDynamic($"nuclei-{templateId}", "GET", uri, matcher),
                    Category = FindingCategory.Dynamic,
                    Severity = severity,
                    RuleId = templateId,
                    Title = Text(info, "name") ?? templateId,
                    Description = string.Join("\n\n", new[]
                    {
                        $"Matched at {matched}{(matcher is null ? "" : $" ({matcher})")}",
                        Text(info, "description")?.Trim(),
                        Text(info, "remediation") is { } fix ? "Fix: " + fix.Trim() : null,
                    }.Where(s => !string.IsNullOrWhiteSpace(s))),
                    Engines = ["nuclei"],
                    Location = new SourceLocation(matched, Snippet: extracted.Count > 0 ? string.Join(", ", extracted) : null),
                    Aliases = aliases.Distinct().ToList(),
                    References = Strings(info, "reference").ToList(),
                });
            }
        }

        return findings;
    }

    private static string? Text(JsonElement element, string name) =>
        element.ValueKind == JsonValueKind.Object && element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;

    /// <summary>nuclei writes some fields as a string or an array of strings depending on the template.</summary>
    private static IEnumerable<string> Strings(JsonElement element, string name)
    {
        if (element.ValueKind != JsonValueKind.Object || !element.TryGetProperty(name, out var value))
        {
            return [];
        }

        return value.ValueKind switch
        {
            JsonValueKind.String => value.GetString() is { Length: > 0 } s ? [s] : [],
            JsonValueKind.Array => value.EnumerateArray().Where(v => v.ValueKind == JsonValueKind.String).Select(v => v.GetString()!).ToList(),
            _ => [],
        };
    }
}
