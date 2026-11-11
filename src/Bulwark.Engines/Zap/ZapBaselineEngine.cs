using System.Diagnostics;
using Bulwark.Core.Dast;
using Bulwark.Core.Engines;
using Bulwark.Engines.Execution;

namespace Bulwark.Engines.Zap;

/// <summary>
/// OWASP ZAP baseline scan: spiders the target and runs passive rules (headers, cookies,
/// information leaks). It sends no attack payloads, so it runs first and doubles as discovery:
/// the URLs it finds feed the AI planner. All traffic goes through the scope proxy.
/// </summary>
public sealed class ZapBaselineEngine(ToolRunner runner) : IDastEngine
{
    private const string ContainerWork = "/zap/wrk";
    private const string ReportFile = "zap.json";

    public string Name => "zap";
    public int Order => 10;

    public async Task<EngineResult> RunAsync(DastContext context, CancellationToken cancellationToken)
    {
        var stopwatch = Stopwatch.StartNew();
        var work = Path.Combine(context.WorkDirectory, "zap");
        Directory.CreateDirectory(work);
        if (!OperatingSystem.IsWindows())
        {
            // ZAP runs as an unprivileged user inside its image and must write the report here.
            File.SetUnixFileMode(work, (UnixFileMode)0b111_111_111);
        }

        var container = runner.IsContainer(Name);
        var proxy = new Uri(container ? context.ContainerProxyUrl : context.LocalProxyUrl);
        var spiderMinutes = Math.Clamp(context.Scope.TimeBudgetMinutes / 6, 1, 5);

        List<string> arguments = container ? ["zap-baseline.py"] : [];
        arguments.AddRange(
        [
            "-t", context.Target.ToString(),
            "-J", ReportFile,
            "-m", spiderMinutes.ToString(System.Globalization.CultureInfo.InvariantCulture),
            "-I",
            "-z", string.Join(' ',
                "-config network.connection.httpProxy.enabled=true",
                $"-config network.connection.httpProxy.host={proxy.Host}",
                $"-config network.connection.httpProxy.port={proxy.Port}",
                "-config network.localServers.mainProxy.behindNat=false",
                "-config start.checkForUpdates=false",
                "-config start.addonUpdate=false"),
        ]);

        var output = await runner.RunAsync(Name, arguments, work, work, context.Remaining,
            cancellationToken, ZapAuth.Environment(context), containerWorkPath: ContainerWork);

        var reportPath = Path.Combine(work, ReportFile);

        // Exit codes: 0 pass, 1 fail, 2 warn are all normal results; 3 means ZAP itself failed.
        if (!File.Exists(reportPath))
        {
            var detail = string.Join(' ', (output.StandardError + output.StandardOutput).Split('\n').TakeLast(5)).Trim();
            return EngineResult.Failed(Name, $"no report (exit {output.ExitCode}): {detail}", stopwatch.Elapsed);
        }

        var (findings, urls) = ZapReportParser.Parse(await File.ReadAllTextAsync(reportPath, cancellationToken));
        context.DiscoveredUrls.AddRange(urls);
        return new EngineResult(Name, findings, stopwatch.Elapsed);
    }
}
