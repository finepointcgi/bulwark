using Nightjar.Core.Findings;
using Nightjar.Core.Monitoring;
using Nightjar.Core.Reports;
using Nightjar.Core.Updates;

namespace Nightjar.Cli;

/// <summary>
/// nightjar monitor [--project path] [--webhook url] [--fail-on high]
/// Re-checks every scanned project's saved SBOM for newly published advisories. Run it daily
/// (cron, a scheduled CI job, or just keep the dashboard running, which does it automatically).
/// Exit 1 when a new advisory at or above --fail-on appeared, so schedulers can alert on it too.
/// </summary>
internal static class MonitorCommand
{
    public static async Task<int> RunAsync(Options options)
    {
        var home = ManifestStore.Default().HomeDirectory;
        using var http = new HttpClient { Timeout = TimeSpan.FromMinutes(2) };
        http.DefaultRequestHeaders.UserAgent.ParseAdd("nightjar-monitor");

        var project = options.Value("project") is { } p ? Path.GetFullPath(p) : null;
        var results = await new AdvisoryMonitor(http, new ReportArchive(home)).CheckAllAsync(project, CancellationToken.None);
        if (results.Count == 0)
        {
            Console.Error.WriteLine("Nothing to monitor yet: scan a project with dependencies first.");
            return 0;
        }

        foreach (var result in results)
        {
            Console.WriteLine($"{result.Project}: {result.PackagesChecked} packages, {result.NewFindings.Count} new advisor{(result.NewFindings.Count == 1 ? "y" : "ies")}");
            foreach (var f in result.NewFindings.OrderByDescending(f => f.Severity))
            {
                var fix = f.FixedVersions.Count > 0 ? $"  → fix: {f.FixedVersions[0]}" : "";
                Console.WriteLine($"  {f.Severity.ToString().ToUpperInvariant(),-9} {f.RuleId,-22} {f.Package?.Name}@{f.Package?.Version}{fix}");
            }
        }

        if ((options.Value("webhook") ?? Environment.GetEnvironmentVariable("NIGHTJAR_WEBHOOK")) is { } webhook)
        {
            await new WebhookNotifier(http, new Uri(webhook)).NotifyAsync(results, CancellationToken.None);
        }

        var failOn = options.Value("fail-on") ?? "high";
        if (failOn.Equals("none", StringComparison.OrdinalIgnoreCase))
        {
            return 0;
        }

        var threshold = Enum.Parse<Severity>(failOn, ignoreCase: true);
        return results.SelectMany(r => r.NewFindings).Any(f => f.Severity >= threshold) ? 1 : 0;
    }
}
