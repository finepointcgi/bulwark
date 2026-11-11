using System.Text.Json;
using System.Text.Json.Nodes;
using Bulwark.Core.Findings;

namespace Bulwark.Core.Reports;

/// <summary>
/// SARIF 2.1.0 output, so results show up natively in GitHub code scanning, GitLab,
/// Azure DevOps and IDE SARIF viewers.
/// </summary>
public static class SarifWriter
{
    public static string Write(ScanReport report, string toolVersion)
    {
        var rules = new JsonArray();
        var ruleIndex = new Dictionary<string, int>(StringComparer.Ordinal);
        var results = new JsonArray();

        foreach (var finding in report.Findings)
        {
            if (!ruleIndex.TryGetValue(finding.RuleId, out var index))
            {
                index = rules.Count;
                ruleIndex[finding.RuleId] = index;
                rules.Add(new JsonObject
                {
                    ["id"] = finding.RuleId,
                    ["shortDescription"] = new JsonObject { ["text"] = finding.Title },
                    ["properties"] = new JsonObject { ["tags"] = new JsonArray(finding.Category.ToString().ToLowerInvariant()) },
                });
            }

            var result = new JsonObject
            {
                ["ruleId"] = finding.RuleId,
                ["ruleIndex"] = index,
                ["level"] = Level(finding.Severity),
                ["message"] = new JsonObject { ["text"] = finding.Description ?? finding.Title },
                ["partialFingerprints"] = new JsonObject { ["bulwark/v1"] = finding.Id },
                ["properties"] = new JsonObject
                {
                    ["severity"] = finding.Severity.ToString(),
                    ["engines"] = new JsonArray(finding.Engines.Select(e => (JsonNode)JsonValue.Create(e)!).ToArray()),
                },
            };

            if (finding.Assessment is { } assessment)
            {
                var properties = (JsonObject)result["properties"]!;
                properties["aiExploitability"] = assessment.Verdict.ToString();
                properties["aiConfidence"] = assessment.Confidence;
                properties["aiReasoning"] = assessment.Reasoning;
                properties["aiModel"] = assessment.Model;
            }

            if (finding.Location?.Path is { } path)
            {
                var region = new JsonObject();
                if (finding.Location.StartLine is { } start)
                {
                    region["startLine"] = start;
                }

                var physical = new JsonObject { ["artifactLocation"] = new JsonObject { ["uri"] = path.Replace('\\', '/') } };
                if (region.Count > 0)
                {
                    physical["region"] = region;
                }

                result["locations"] = new JsonArray(new JsonObject { ["physicalLocation"] = physical });
            }

            results.Add(result);
        }

        var sarif = new JsonObject
        {
            ["$schema"] = "https://json.schemastore.org/sarif-2.1.0.json",
            ["version"] = "2.1.0",
            ["runs"] = new JsonArray(new JsonObject
            {
                ["tool"] = new JsonObject
                {
                    ["driver"] = new JsonObject
                    {
                        ["name"] = "Bulwark",
                        ["version"] = toolVersion,
                        ["rules"] = rules,
                    },
                },
                ["results"] = results,
            }),
        };

        return sarif.ToJsonString(new JsonSerializerOptions { WriteIndented = true });
    }

    private static string Level(Severity severity) => severity switch
    {
        Severity.Critical or Severity.High => "error",
        Severity.Medium => "warning",
        _ => "note",
    };
}
