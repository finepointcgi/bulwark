using Nightjar.Core.Monitoring;
using Nightjar.Core.Reports;

namespace Nightjar.Web;

/// <summary>
/// While the dashboard runs, re-check every project's SBOM for new advisories once a day and
/// post to the configured webhook (Nightjar:Webhook or NIGHTJAR_WEBHOOK). Disable with
/// Nightjar:Monitor=false.
/// </summary>
public sealed class MonitorService(ReportArchive archive, IConfiguration configuration, ILogger<MonitorService> logger) : BackgroundService
{
    private static readonly TimeSpan Interval = TimeSpan.FromHours(24);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (configuration.GetValue("Nightjar:Monitor", true) is false)
        {
            return;
        }

        var webhook = configuration["Nightjar:Webhook"] ?? Environment.GetEnvironmentVariable("NIGHTJAR_WEBHOOK");
        using var http = new HttpClient { Timeout = TimeSpan.FromMinutes(2) };
        http.DefaultRequestHeaders.UserAgent.ParseAdd("nightjar-monitor");

        // Short delay so startup is not slowed down, then daily.
        await Task.Delay(TimeSpan.FromMinutes(1), stoppingToken);
        using var timer = new PeriodicTimer(Interval);
        do
        {
            try
            {
                var results = await new AdvisoryMonitor(http, archive).CheckAllAsync(null, stoppingToken);
                var count = results.Sum(r => r.NewFindings.Count);
                logger.LogInformation("Advisory monitor: {Projects} project(s) checked, {New} new advisories", results.Count, count);
                if (count > 0 && webhook is not null)
                {
                    await new WebhookNotifier(http, new Uri(webhook)).NotifyAsync(results, stoppingToken);
                }
            }
            catch (Exception e) when (e is HttpRequestException or TaskCanceledException or IOException or System.Text.Json.JsonException)
            {
                logger.LogWarning(e, "Advisory monitor run failed; will retry next interval");
            }
        }
        while (await timer.WaitForNextTickAsync(stoppingToken));
    }
}
