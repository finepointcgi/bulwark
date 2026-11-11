using System.Text;
using Nightjar.Core.Findings;
using Nightjar.Core.Reports;

namespace Nightjar.Cli;

/// <summary>
/// Short markdown summary for PR comments and CI job summaries ($GITHUB_STEP_SUMMARY).
/// Leads with what blocks the merge; everything else is folded away.
/// </summary>
internal static class MarkdownWriter
{
    /// <summary>Hidden marker so CI can find and update its previous comment instead of adding new ones.</summary>
    public const string Marker = "<!-- nightjar-report -->";

    private const int MaxRows = 25;

    public static string Write(ScanReport report, IReadOnlySet<string>? newIds, string failOn)
    {
        var active = report.Findings.Where(f => f.Triage is TriageState.New or TriageState.Confirmed).ToList();
        var threshold = failOn.Equals("none", StringComparison.OrdinalIgnoreCase)
            ? (Severity?)null
            : Enum.Parse<Severity>(failOn, ignoreCase: true);
        var considered = newIds is null ? active : active.Where(f => newIds.Contains(f.Id)).ToList();
        var blocking = threshold is { } t ? considered.Where(f => f.Severity >= t).ToList() : [];

        var md = new StringBuilder();
        md.AppendLine(Marker);
        md.AppendLine(blocking.Count == 0
            ? "### ✅ Nightjar: quality gate passed"
            : $"### ❌ Nightjar: {blocking.Count} {(newIds is null ? "" : "new ")}finding(s) at {failOn} or above");
        md.AppendLine();

        var counts = active.GroupBy(f => f.Severity).OrderByDescending(g => g.Key).Select(g => $"{g.Count()} {g.Key.ToString().ToLowerInvariant()}");
        md.Append($"{active.Count} open finding(s)");
        if (active.Count > 0) { md.Append($": {string.Join(", ", counts)}"); }
        if (newIds is not null) { md.Append($" · **{considered.Count} new in this change**"); }
        var triaged = report.Findings.Count - active.Count;
        if (triaged > 0) { md.Append($" · {triaged} triaged"); }
        md.AppendLine();
        md.AppendLine();

        if (blocking.Count > 0)
        {
            AppendTable(md, blocking);
        }

        var other = considered.Except(blocking).ToList();
        if (other.Count > 0)
        {
            md.AppendLine($"<details><summary>{other.Count} other {(newIds is null ? "" : "new ")}finding(s)</summary>");
            md.AppendLine();
            AppendTable(md, other);
            md.AppendLine("</details>");
            md.AppendLine();
        }

        var failed = report.Engines.Where(e => !e.Succeeded).ToList();
        if (failed.Count > 0)
        {
            md.AppendLine($"⚠️ Engines that failed: {string.Join(", ", failed.Select(e => e.Engine))}. Their results are missing from this report.");
            md.AppendLine();
        }

        if (QualityGates.Summary(report) is { Length: > 0 } metrics)
        {
            md.AppendLine($"**Code quality:** {metrics}");
            md.AppendLine();
        }

        md.AppendLine($"<sub>{string.Join(" · ", report.Engines.Select(e => $"{e.Engine} {e.Version}"))} · manifest #{report.ManifestSequence} · "
            + "mark false positives with `nightjar triage <id> false-positive --reason \"...\" --shared`</sub>");
        return md.ToString();
    }

    private static void AppendTable(StringBuilder md, List<Finding> findings)
    {
        md.AppendLine("| Severity | Finding | Where | Fix | Id |");
        md.AppendLine("|---|---|---|---|---|");
        foreach (var f in findings.OrderByDescending(f => f.Severity).Take(MaxRows))
        {
            var where = f.Location?.Path is { } p ? (f.Location.StartLine is { } l ? $"`{p}:{l}`" : $"`{p}`") : "";
            var fix = f.FixedVersions.Count > 0 ? $"upgrade to {f.FixedVersions[0]}" : "";
            md.AppendLine($"| {f.Severity} | {Escape(f.Title)} | {where} | {fix} | `{f.Id[..12]}` |");
        }

        if (findings.Count > MaxRows)
        {
            md.AppendLine($"\n…and {findings.Count - MaxRows} more. See the SARIF results or the dashboard.");
        }

        md.AppendLine();
    }

    private static string Escape(string text) => text.Replace("|", "\\|").Replace("\n", " ");
}
