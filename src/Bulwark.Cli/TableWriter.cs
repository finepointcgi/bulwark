using System.Text;
using Bulwark.Core.Findings;
using Bulwark.Core.Reports;

namespace Bulwark.Cli;

internal static class TableWriter
{
    public static string Write(ScanReport report)
    {
        var text = new StringBuilder();
        text.AppendLine();
        text.AppendLine($"Scanned {report.Project} in {report.Seconds:0.0}s with {string.Join(", ", report.Engines.Select(e => $"{e.Engine} {e.Version}"))}");
        if (QualityGates.Summary(report) is { Length: > 0 } metrics)
        {
            text.AppendLine($"Code quality: {metrics}");
        }

        if (report.Findings.Count == 0)
        {
            text.AppendLine("No findings.");
            return text.ToString();
        }

        var counts = report.Findings.GroupBy(f => f.Severity).OrderByDescending(g => g.Key).Select(g => $"{g.Count()} {g.Key}");
        text.AppendLine($"{report.Findings.Count} findings: {string.Join(", ", counts)}");
        text.AppendLine();

        foreach (var finding in report.Findings)
        {
            var fix = finding.FixedVersions.Count > 0 ? $"  → fix: {string.Join(" / ", finding.FixedVersions)}" : "";
            var where = finding.Location?.Path is { } path
                ? finding.Location.StartLine is { } line ? $"  ({path}:{line})" : $"  ({path})"
                : "";
            var triaged = finding.Triage is TriageState.New or TriageState.Confirmed ? "" : $"  [{finding.Triage}]";
            if (finding.Reachability == Reachability.NotImported) { triaged += "  [not imported directly]"; }
            text.AppendLine($"{Label(finding.Severity),-9} {finding.Category,-14} {finding.RuleId,-22} {finding.Title}{fix}{where}{triaged}");
            if (finding.Assessment is { } ai)
            {
                text.AppendLine($"          AI: {Verdict(ai.Verdict)} ({ai.Confidence:P0}) {ai.Reasoning}");
                foreach (var step in ai.AttackPath)
                {
                    text.AppendLine($"              - {step}");
                }
            }
        }

        return text.ToString();
    }

    private static string Verdict(Bulwark.Core.Ai.Exploitability verdict) => verdict switch
    {
        Bulwark.Core.Ai.Exploitability.Likely => "LIKELY EXPLOITABLE",
        Bulwark.Core.Ai.Exploitability.Possible => "possibly exploitable",
        Bulwark.Core.Ai.Exploitability.NotExploitable => "not exploitable",
        _ => "unknown",
    };

    private static string Label(Severity severity) => severity.ToString().ToUpperInvariant();
}
