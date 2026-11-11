using System.Net;
using System.Text.Json;
using System.Text.RegularExpressions;
using Bulwark.Core.Findings;

namespace Bulwark.Engines.Zap;

/// <summary>Maps ZAP's traditional JSON report (-J) to findings: one finding per alert and URL.</summary>
public static partial class ZapReportParser
{
    private const int MaxInstancesPerAlert = 10;

    public static (IReadOnlyList<Finding> Findings, IReadOnlyList<string> Urls) Parse(string json)
    {
        var findings = new List<Finding>();
        var urls = new HashSet<string>(StringComparer.Ordinal);
        using var document = JsonDocument.Parse(json);

        foreach (var site in Array(document.RootElement, "site"))
        {
            foreach (var alert in Array(site, "alerts"))
            {
                var pluginId = Text(alert, "pluginid") ?? "unknown";
                var title = Text(alert, "alert") ?? Text(alert, "name") ?? "ZAP alert";
                var severity = Text(alert, "riskcode") switch
                {
                    "3" => Severity.High,
                    "2" => Severity.Medium,
                    "1" => Severity.Low,
                    _ => Severity.Info,
                };

                var description = StripHtml(Text(alert, "desc"));
                var solution = StripHtml(Text(alert, "solution"));
                var references = UrlPattern().Matches(Text(alert, "reference") ?? "").Select(m => m.Value).Distinct().ToList();
                var cwe = Text(alert, "cweid") is { } c && c != "-1" && c != "0" ? $"CWE-{c}" : null;

                foreach (var instance in Array(alert, "instances").Take(MaxInstancesPerAlert))
                {
                    if (Text(instance, "uri") is not { } uriText || !Uri.TryCreate(uriText, UriKind.Absolute, out var uri))
                    {
                        continue;
                    }

                    urls.Add(uriText);
                    var method = Text(instance, "method") ?? "GET";
                    var parameter = Text(instance, "param") is { Length: > 0 } p ? p : null;
                    var evidence = Text(instance, "evidence") is { Length: > 0 } e ? e : null;

                    findings.Add(new Finding
                    {
                        Id = Fingerprint.ForDynamic($"zap-{pluginId}", method, uri, parameter),
                        Category = FindingCategory.Dynamic,
                        Severity = severity,
                        RuleId = $"ZAP-{pluginId}",
                        Title = title,
                        Description = string.Join("\n\n", new[]
                        {
                            $"{method} {uriText}{(parameter is null ? "" : $" (parameter: {parameter})")}",
                            description,
                            solution is null ? null : "Fix: " + solution,
                        }.Where(s => s is not null)),
                        Engines = ["zap"],
                        // Dynamic findings locate by URL rather than file path; SARIF accepts absolute URIs.
                        Location = new SourceLocation(uriText, Snippet: evidence),
                        Aliases = cwe is null ? [] : [cwe],
                        References = references,
                    });
                }
            }
        }

        return (findings, urls.ToList());
    }

    private static IEnumerable<JsonElement> Array(JsonElement element, string name) =>
        element.ValueKind == JsonValueKind.Object && element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.Array
            ? value.EnumerateArray()
            : [];

    private static string? Text(JsonElement element, string name) =>
        element.TryGetProperty(name, out var value) ? value.ValueKind switch
        {
            JsonValueKind.String => value.GetString(),
            JsonValueKind.Number => value.GetRawText(),
            _ => null,
        } : null;

    internal static string? StripHtml(string? html)
    {
        if (string.IsNullOrWhiteSpace(html))
        {
            return null;
        }

        var text = WebUtility.HtmlDecode(Tags().Replace(html.Replace("</p>", "\n"), ""));
        return string.Join('\n', text.Split('\n').Select(l => l.Trim()).Where(l => l.Length > 0));
    }

    [GeneratedRegex("<[^>]+>")]
    private static partial Regex Tags();

    [GeneratedRegex(@"https?://[^\s<""]+")]
    private static partial Regex UrlPattern();
}
