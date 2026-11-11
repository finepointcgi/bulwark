using System.Diagnostics;
using System.Text.Json;
using System.Text.RegularExpressions;
using Bulwark.Core.Engines;
using Bulwark.Core.Findings;
using Bulwark.Engines.Execution;

namespace Bulwark.Engines.Trivy;

/// <summary>An image to scan and where it came from (the Dockerfile line, or the command line).</summary>
public sealed record ImageTarget(string Reference, string? Dockerfile, int? Line);

/// <summary>
/// Known vulnerabilities in container images with Trivy: the base image of every Dockerfile
/// (final stage, which is what ships) plus any image passed with --image. Images are pulled
/// from their registry by Trivy itself, so no Docker socket is mounted. Only vulnerabilities
/// with a fixed version are reported by default, since the rest are not actionable.
/// </summary>
public sealed partial class TrivyImageEngine(ToolRunner runner, IReadOnlyList<string>? extraImages = null, bool includeUnfixed = false) : IEngine
{
    public string Name => "trivy-image";
    public string ManifestName => "trivy";
    public int Order => 55;

    public bool AppliesTo(ScanContext context) =>
        extraImages is { Count: > 0 } || (context.Profile.HasContainers && FindBaseImages(context.RootPath).Count > 0);

    public async Task<EngineResult> RunAsync(ScanContext context, CancellationToken cancellationToken)
    {
        var stopwatch = Stopwatch.StartNew();
        var targets = FindBaseImages(context.RootPath)
            .Concat((extraImages ?? []).Select(i => new ImageTarget(i, null, null)))
            .DistinctBy(t => t.Reference)
            .ToList();

        var findings = new List<Finding>();
        var errors = new List<string>();
        for (var i = 0; i < targets.Count; i++)
        {
            var target = targets[i];
            var reportFile = $"trivy-image-{i}.json";
            string[] args =
            [
                "image", "--cache-dir", ToolRunner.CacheToken, "--image-src", "remote", "--scanners", "vuln",
                "--format", "json", "--output", $"{ToolRunner.WorkToken}/{reportFile}", "--quiet", "--exit-code", "0",
                .. includeUnfixed ? Array.Empty<string>() : ["--ignore-unfixed"],
                target.Reference,
            ];

            var output = await runner.RunAsync("trivy", args, context.RootPath, context.WorkDirectory,
                TimeSpan.FromMinutes(15), cancellationToken, new Dictionary<string, string> { ["HOME"] = "/tmp" });

            var reportPath = Path.Combine(context.WorkDirectory, reportFile);
            if (output.ExitCode != 0 || !File.Exists(reportPath))
            {
                errors.Add($"{target.Reference}: {LastLine(output.StandardError)}");
                continue;
            }

            findings.AddRange(Parse(await File.ReadAllTextAsync(reportPath, cancellationToken), target, Name));
        }

        // One unreachable image (private registry, typo) should not hide the others' results.
        return new EngineResult(Name, findings, stopwatch.Elapsed, errors.Count == 0 ? null : string.Join("; ", errors));
    }

    public static IReadOnlyList<Finding> Parse(string json, ImageTarget target, string engine)
    {
        using var document = JsonDocument.Parse(json);
        var findings = new List<Finding>();
        if (!document.RootElement.TryGetProperty("Results", out var results) || results.ValueKind != JsonValueKind.Array)
        {
            return findings;
        }

        foreach (var result in results.EnumerateArray())
        {
            if (!result.TryGetProperty("Vulnerabilities", out var vulns) || vulns.ValueKind != JsonValueKind.Array)
            {
                continue;
            }

            var type = Str(result, "Type") ?? "os";
            foreach (var v in vulns.EnumerateArray())
            {
                var id = Str(v, "VulnerabilityID") ?? "UNKNOWN";
                // The image is part of the ecosystem so the same package in two images stays two findings.
                var package = new PackageRef(Str(v, "PkgName") ?? "", Str(v, "InstalledVersion") ?? "", $"{type} ({target.Reference})");
                var fixedVersions = (Str(v, "FixedVersion") ?? "").Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries).ToList();
                findings.Add(new Finding
                {
                    Id = Fingerprint.ForVulnerability(package, id, []),
                    Category = FindingCategory.Vulnerability,
                    Severity = (Str(v, "Severity") ?? "").ToUpperInvariant() switch
                    {
                        "CRITICAL" => Severity.Critical,
                        "HIGH" => Severity.High,
                        "MEDIUM" => Severity.Medium,
                        "LOW" => Severity.Low,
                        _ => Severity.Unknown,
                    },
                    RuleId = id,
                    Title = $"{Str(v, "Title") ?? id} in {package.Name}@{package.Version} (image {target.Reference})",
                    Description = Str(v, "Description"),
                    Package = package,
                    Location = target.Dockerfile is null ? null : new SourceLocation(target.Dockerfile, target.Line),
                    FixedVersions = fixedVersions,
                    References = Str(v, "PrimaryURL") is { } url ? [url] : [],
                    Engines = [engine],
                });
            }
        }

        return findings;
    }

    /// <summary>
    /// The final-stage base image of each Dockerfile. Skips build-stage aliases and scratch, and
    /// resolves ${ARG} references from ARG defaults declared before FROM. Unresolvable ones are skipped.
    /// </summary>
    public static IReadOnlyList<ImageTarget> FindBaseImages(string root)
    {
        var targets = new List<ImageTarget>();
        foreach (var file in ProjectDetector.EnumerateFiles(root))
        {
            var name = Path.GetFileName(file);
            if (!name.Equals("Dockerfile", StringComparison.OrdinalIgnoreCase) && !name.EndsWith(".dockerfile", StringComparison.OrdinalIgnoreCase)
                && !name.StartsWith("Dockerfile.", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (ParseDockerfile(File.ReadAllLines(file)) is { } final)
            {
                targets.Add(new ImageTarget(final.Image, Path.GetRelativePath(root, file).Replace('\\', '/'), final.Line));
            }
        }

        return targets;
    }

    internal static (string Image, int Line)? ParseDockerfile(string[] lines)
    {
        var args = new Dictionary<string, string>(StringComparer.Ordinal);
        var stages = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        (string Image, int Line)? last = null;

        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i].Trim();
            if (ArgLine().Match(line) is { Success: true } arg && last is null)
            {
                args[arg.Groups[1].Value] = arg.Groups[2].Value.Trim('"', '\'');
                continue;
            }

            if (FromLine().Match(line) is not { Success: true } from)
            {
                continue;
            }

            var image = Variable().Replace(from.Groups[1].Value, m => args.GetValueOrDefault(m.Groups[1].Value + m.Groups[2].Value, m.Value));
            var isEarlierStage = stages.Contains(image);
            if (from.Groups[2].Success)
            {
                stages.Add(from.Groups[2].Value);
            }

            // FROM <earlier stage> means the final image's base is that stage's base: keep the previous answer.
            if (isEarlierStage)
            {
                continue;
            }

            last = image.Contains('$') || image.Equals("scratch", StringComparison.OrdinalIgnoreCase) ? null : (image, i + 1);
        }

        return last;
    }

    private static string LastLine(string text) =>
        text.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).LastOrDefault() ?? "failed";

    private static string? Str(JsonElement element, string property) =>
        element.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;

    [GeneratedRegex(@"^ARG\s+([A-Za-z_][A-Za-z0-9_]*)=(\S+)", RegexOptions.IgnoreCase)]
    private static partial Regex ArgLine();

    [GeneratedRegex(@"^FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?", RegexOptions.IgnoreCase)]
    private static partial Regex FromLine();

    [GeneratedRegex(@"\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)")]
    private static partial Regex Variable();
}
