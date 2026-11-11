using System.Net.Http.Json;
using System.Text;
using Nightjar.Core.Findings;

namespace Nightjar.Core.Monitoring;

/// <summary>
/// Posts monitoring alerts to a chat webhook. The payload carries both <c>text</c> (Slack, Mattermost,
/// Teams workflows) and <c>content</c> (Discord), so one URL works with most chat tools.
/// </summary>
public sealed class WebhookNotifier(HttpClient http, Uri webhook)
{
    public async Task NotifyAsync(IReadOnlyList<MonitorResult> results, CancellationToken cancellationToken)
    {
        var withNews = results.Where(r => r.NewFindings.Count > 0).ToList();
        if (withNews.Count == 0)
        {
            return;
        }

        var message = Format(withNews);
        using var response = await http.PostAsJsonAsync(webhook, new { text = message, content = message }, cancellationToken);
        response.EnsureSuccessStatusCode();
    }

    public static string Format(IReadOnlyList<MonitorResult> results)
    {
        var text = new StringBuilder();
        var total = results.Sum(r => r.NewFindings.Count);
        text.AppendLine($"Nightjar: {total} new advisor{(total == 1 ? "y" : "ies")} affect dependencies you already ship.");
        foreach (var result in results)
        {
            text.AppendLine();
            text.AppendLine($"{Path.GetFileName(result.Project.TrimEnd('/', '\\'))} ({result.Project})");
            foreach (var f in result.NewFindings.OrderByDescending(f => f.Severity).Take(10))
            {
                var fix = f.FixedVersions.Count > 0 ? $" (fixed in {f.FixedVersions[0]})" : "";
                text.AppendLine($"• {f.Severity.ToString().ToUpperInvariant()} {f.RuleId}: {f.Package?.Name}@{f.Package?.Version}{fix}");
            }

            if (result.NewFindings.Count > 10)
            {
                text.AppendLine($"• …and {result.NewFindings.Count - 10} more");
            }
        }

        return text.ToString().TrimEnd();
    }
}
