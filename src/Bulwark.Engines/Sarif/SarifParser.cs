using System.Globalization;
using System.Text.Json;
using Bulwark.Core.Findings;
using Bulwark.Engines.Execution;

namespace Bulwark.Engines.Sarif;

/// <summary>
/// Generic SARIF 2.1.0 reader. Most SAST tools (Opengrep, gosec, Bandit, SpotBugs, ESLint,
/// Roslyn analyzers) can emit SARIF, so new engines usually only need this plus a command line.
/// </summary>
public static class SarifParser
{
    public static IReadOnlyList<Finding> Parse(
        string json,
        string sourcePath,
        string engine,
        FindingCategory category,
        Func<string, string>? normalizeRuleId = null)
    {
        normalizeRuleId ??= id => id;
        using var document = JsonDocument.Parse(json);
        var findings = new List<Finding>();
        if (!document.RootElement.TryGetProperty("runs", out var runs))
        {
            return findings;
        }

        foreach (var run in runs.EnumerateArray())
        {
            var rules = ReadRules(run);
            if (!run.TryGetProperty("results", out var results))
            {
                continue;
            }

            findings.AddRange(results.EnumerateArray().Select(result => ToFinding(result, rules, sourcePath, engine, category, normalizeRuleId)));
        }

        return findings;
    }

    private static Finding ToFinding(
        JsonElement result, Dictionary<string, RuleInfo> rules, string sourcePath, string engine, FindingCategory category, Func<string, string> normalizeRuleId)
    {
        var rawRuleId = Str(result, "ruleId") ?? "unknown";
        rules.TryGetValue(rawRuleId, out var rule);
        var ruleId = normalizeRuleId(rawRuleId);

        var (path, line, snippet) = ReadLocation(result, sourcePath);
        snippet ??= path is null ? null : ReadSourceLines(sourcePath, path, line, line);

        var message = result.TryGetProperty("message", out var m) ? Str(m, "text") : null;
        return new Finding
        {
            Id = Fingerprint.ForCode(ruleId, path ?? "", snippet, line),
            Category = category,
            Severity = SeverityOf(result, rule),
            RuleId = ruleId,
            Title = rule?.Title ?? message ?? ruleId,
            Description = message ?? rule?.Title,
            Location = path is null ? null : new SourceLocation(path, line, null, snippet?.Trim()),
            References = rule?.HelpUri is { } uri ? [uri] : [],
            Aliases = rule?.Cwes ?? [],
            Engines = [engine],
        };
    }

    private sealed record RuleInfo(string? Title, string? DefaultLevel, double? SecuritySeverity, string? HelpUri, List<string> Cwes);

    private static Dictionary<string, RuleInfo> ReadRules(JsonElement run)
    {
        var rules = new Dictionary<string, RuleInfo>(StringComparer.Ordinal);
        if (!run.TryGetProperty("tool", out var tool) || !tool.TryGetProperty("driver", out var driver)
            || !driver.TryGetProperty("rules", out var list))
        {
            return rules;
        }

        foreach (var rule in list.EnumerateArray())
        {
            if (Str(rule, "id") is not { } id)
            {
                continue;
            }

            var title = rule.TryGetProperty("shortDescription", out var s) ? Str(s, "text") : null;
            var level = rule.TryGetProperty("defaultConfiguration", out var config) ? Str(config, "level") : null;
            var (securitySeverity, cwes) = ReadProperties(rule);

            // Opengrep repeats the full message as shortDescription; keep titles to one line.
            if (title is not null && (title.StartsWith("Opengrep Finding:", StringComparison.Ordinal) || title.StartsWith("Semgrep Finding:", StringComparison.Ordinal)))
            {
                title = null;
            }

            rules[id] = new RuleInfo(title, level, securitySeverity, Str(rule, "helpUri"), cwes);
        }

        return rules;
    }

    private static (double? SecuritySeverity, List<string> Cwes) ReadProperties(JsonElement rule)
    {
        double? securitySeverity = null;
        var cwes = new List<string>();
        if (!rule.TryGetProperty("properties", out var properties))
        {
            return (null, cwes);
        }

        if (properties.TryGetProperty("security-severity", out var score))
        {
            securitySeverity = score.ValueKind switch
            {
                JsonValueKind.Number => score.GetDouble(),
                JsonValueKind.String when double.TryParse(score.GetString(), NumberStyles.Float, CultureInfo.InvariantCulture, out var d) => d,
                _ => null,
            };
        }

        if (properties.TryGetProperty("tags", out var tags) && tags.ValueKind == JsonValueKind.Array)
        {
            cwes.AddRange(tags.EnumerateArray()
                .Select(t => t.GetString() ?? "")
                .Where(t => t.StartsWith("CWE-", StringComparison.OrdinalIgnoreCase))
                .Select(t => t.Split(':')[0].Trim()));
        }

        return (securitySeverity, cwes);
    }

    private static Severity SeverityOf(JsonElement result, RuleInfo? rule)
    {
        if (rule?.SecuritySeverity is { } score)
        {
            return score switch { >= 9.0 => Severity.Critical, >= 7.0 => Severity.High, >= 4.0 => Severity.Medium, > 0 => Severity.Low, _ => Severity.Info };
        }

        return (Str(result, "level") ?? rule?.DefaultLevel) switch
        {
            "error" => Severity.High,
            "warning" => Severity.Medium,
            "note" => Severity.Low,
            "none" => Severity.Info,
            _ => Severity.Medium, // SARIF's default level is "warning".
        };
    }

    private static (string? Path, int? Line, string? Snippet) ReadLocation(JsonElement result, string sourcePath)
    {
        if (!result.TryGetProperty("locations", out var locations) || locations.GetArrayLength() == 0
            || !locations[0].TryGetProperty("physicalLocation", out var physical))
        {
            return (null, null, null);
        }

        var uri = physical.TryGetProperty("artifactLocation", out var artifact) ? Str(artifact, "uri") : null;
        int? line = null;
        string? snippet = null;
        if (physical.TryGetProperty("region", out var region))
        {
            if (region.TryGetProperty("startLine", out var start) && start.TryGetInt32(out var l))
            {
                line = l;
            }

            if (region.TryGetProperty("snippet", out var s))
            {
                snippet = Str(s, "text");
            }
        }

        var path = uri is null ? null : ToolRunner.ToProjectPath(Uri.UnescapeDataString(uri.Replace("file://", "")), sourcePath);
        return (path, line, snippet);
    }

    /// <summary>Reads lines from the scanned file when the engine did not include a snippet.</summary>
    internal static string? ReadSourceLines(string sourcePath, string relativePath, int? startLine, int? endLine)
    {
        if (startLine is not { } start)
        {
            return null;
        }

        try
        {
            var full = Path.GetFullPath(Path.Combine(sourcePath, relativePath));
            if (!full.StartsWith(Path.GetFullPath(sourcePath), StringComparison.Ordinal) || !File.Exists(full))
            {
                return null;
            }

            var lines = File.ReadLines(full).Skip(start - 1).Take(Math.Max(1, (endLine ?? start) - start + 1));
            return string.Join('\n', lines);
        }
        catch (IOException)
        {
            return null;
        }
    }

    private static string? Str(JsonElement element, string property) =>
        element.ValueKind == JsonValueKind.Object && element.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;
}
