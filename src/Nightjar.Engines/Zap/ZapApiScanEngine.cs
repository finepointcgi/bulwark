using System.Diagnostics;
using System.Globalization;
using System.Text.Json;
using System.Text.RegularExpressions;
using Nightjar.Core.Dast;
using Nightjar.Core.Engines;
using Nightjar.Engines.Execution;

namespace Nightjar.Engines.Zap;

/// <summary>
/// ZAP's API scan, driven by an OpenAPI spec, so it reaches endpoints a crawler can't find.
/// Runs in safe mode (import, explore, passive rules) unless the scope sets allowActiveScan,
/// and the spec's servers are overridden with the scope target, so a spec that names production
/// can't redirect the test. Methods the scope doesn't allow are blocked by the proxy as usual.
/// </summary>
public sealed partial class ZapApiScanEngine(ToolRunner runner) : IDastEngine
{
    private const string ContainerWork = "/zap/wrk";
    private const string ReportFile = "zap-api.json";

    public string Name => "zap-api";
    public int Order => 20;

    public async Task<EngineResult> RunAsync(DastContext context, CancellationToken cancellationToken)
    {
        var stopwatch = Stopwatch.StartNew();
        if (context.OpenApi is not { } spec)
        {
            return new EngineResult(Name, [], stopwatch.Elapsed);
        }

        var work = Path.Combine(context.WorkDirectory, "zap-api");
        Directory.CreateDirectory(work);
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(work, (UnixFileMode)0b111_111_111);
        }

        string specArgument;
        if (Uri.TryCreate(spec, UriKind.Absolute, out var specUri) && specUri.Scheme is "http" or "https")
        {
            if (context.Scope.Check("GET", specUri) is { Allowed: false } decision)
            {
                return EngineResult.Failed(Name, $"OpenAPI URL is out of scope: {decision.Reason}", stopwatch.Elapsed);
            }

            specArgument = spec;
        }
        else
        {
            var name = "openapi" + Path.GetExtension(spec);
            File.Copy(spec, Path.Combine(work, name), overwrite: true);
            if (!OperatingSystem.IsWindows())
            {
                File.SetUnixFileMode(Path.Combine(work, name), (UnixFileMode)0b110_100_100);
            }

            specArgument = $"{ContainerWork}/{name}";
            context.DiscoveredUrls.AddRange(SpecPaths(await File.ReadAllTextAsync(spec, cancellationToken)).Select(p => new Uri(context.Target, p.TrimStart('/')).ToString()));
        }

        var container = runner.IsContainer("zap");
        var proxy = new Uri(container ? context.ContainerProxyUrl : context.LocalProxyUrl);
        List<string> arguments = container ? ["zap-api-scan.py"] : [];
        arguments.AddRange(
        [
            "-t", specArgument,
            "-f", "openapi",
            "-O", context.Target.GetLeftPart(UriPartial.Authority),
            "-J", ReportFile,
            "-I",
            "-T", Math.Clamp((int)context.Remaining.TotalMinutes, 1, 60).ToString(CultureInfo.InvariantCulture),
            "-z", string.Join(' ',
                "-config network.connection.httpProxy.enabled=true",
                $"-config network.connection.httpProxy.host={proxy.Host}",
                $"-config network.connection.httpProxy.port={proxy.Port}",
                "-config start.checkForUpdates=false",
                "-config start.addonUpdate=false"),
        ]);

        if (!context.Scope.AllowActiveScan)
        {
            arguments.Add("-S");
        }

        // The API scan runs from the same pinned ZAP image as the baseline.
        var output = await runner.RunAsync("zap", arguments, work, work, context.Remaining,
            cancellationToken, ZapAuth.Environment(context), containerWorkPath: ContainerWork);

        var reportPath = Path.Combine(work, ReportFile);
        if (!File.Exists(reportPath))
        {
            var detail = string.Join(' ', (output.StandardError + output.StandardOutput).Split('\n').TakeLast(5)).Trim();
            return EngineResult.Failed(Name, $"no report (exit {output.ExitCode}): {detail}", stopwatch.Elapsed);
        }

        var (findings, urls) = ZapReportParser.Parse(await File.ReadAllTextAsync(reportPath, cancellationToken));
        context.DiscoveredUrls.AddRange(urls);
        return new EngineResult(Name, findings.Select(f => f with { Engines = ["zap-api"] }).ToList(), stopwatch.Elapsed);
    }

    /// <summary>Endpoint paths in an OpenAPI document (JSON, or YAML by a line match), for the planner.</summary>
    internal static IReadOnlyList<string> SpecPaths(string document)
    {
        try
        {
            using var json = JsonDocument.Parse(document);
            return json.RootElement.TryGetProperty("paths", out var paths) && paths.ValueKind == JsonValueKind.Object
                ? paths.EnumerateObject().Select(p => p.Name).Where(p => p.StartsWith('/')).ToList()
                : [];
        }
        catch (JsonException)
        {
            return YamlPath().Matches(document).Select(m => m.Groups[1].Value.Trim('\'', '"')).Distinct().ToList();
        }
    }

    [GeneratedRegex(@"^\s{2}(['""]?/[^\s:'""]*['""]?)\s*:\s*$", RegexOptions.Multiline)]
    private static partial Regex YamlPath();
}
