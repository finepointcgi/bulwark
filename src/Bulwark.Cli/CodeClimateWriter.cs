using System.Text.Json;
using Bulwark.Core.Findings;
using Bulwark.Core.Reports;

namespace Bulwark.Cli;

/// <summary>
/// GitLab code quality report (CodeClimate JSON subset), so findings appear in the merge request
/// widget and inline in the diff on GitLab, which has no native SARIF support.
/// </summary>
internal static class CodeClimateWriter
{
    public static string Write(ScanReport report)
    {
        var issues = report.Findings
            .Where(f => f.Triage is TriageState.New or TriageState.Confirmed)
            .Select(f => new
            {
                description = f.Title,
                check_name = f.RuleId,
                fingerprint = f.Id,
                severity = f.Severity switch
                {
                    Severity.Critical => "blocker",
                    Severity.High => "critical",
                    Severity.Medium => "major",
                    Severity.Low => "minor",
                    _ => "info",
                },
                categories = new[] { "Security" },
                location = new
                {
                    path = f.Location?.Path ?? ".",
                    lines = new { begin = f.Location?.StartLine ?? 1 },
                },
            });

        return JsonSerializer.Serialize(issues, new JsonSerializerOptions { WriteIndented = true });
    }
}
