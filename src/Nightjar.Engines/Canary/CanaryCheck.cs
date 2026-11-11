using Nightjar.Core.Engines;
using Nightjar.Core.Reports;
using Nightjar.Core.Updates;

namespace Nightjar.Engines.Canary;

public sealed record CanaryExpectation(string Engine, string RuleId);

public sealed record CanaryResult(
    bool Passed,
    IReadOnlyList<CanaryExpectation> Missing,
    IReadOnlyList<EngineRun> FailedEngines,
    ScanReport Report);

/// <summary>
/// Scans the built-in vulnerable corpus and checks that every engine still finds what it should.
/// Used before accepting new engine versions: by the engine-watch workflow before opening a PR,
/// and on every client after installing a manifest (failing → automatic rollback).
/// </summary>
public static class CanaryCheck
{
    public static readonly IReadOnlyList<CanaryExpectation> Expectations =
    [
        new("osv-scanner", "GHSA-35jh-r3h4-6jhm"),
        new("gitleaks", "secret/github-pat"),
        new("opengrep", "nightjar.csharp.insecure-deserialization"),
        new("opengrep", "nightjar.js.eval"),
        new("opengrep", "nightjar.python.subprocess-shell"),
        new("opengrep", "nightjar.go.tls-validation-disabled"),
        new("opengrep", "nightjar.taint.python.injection"),
        new("opengrep", "nightjar.taint.js.xss"),
        new("opengrep", "nightjar.c.unbounded-copy"),
        new("opengrep", "nightjar.taint.java.spring-injection"),
        new("opengrep", "nightjar.taint.csharp.action-parameter"),
        new("opengrep", "nightjar.taint.php.injection"),
        new("opengrep", "nightjar.taint.php.xss"),
        new("opengrep", "nightjar.taint.ruby.injection"),
        new("opengrep", "nightjar.rust.command-shell"),
        new("opengrep", "nightjar.kotlin.runtime-exec"),
        new("opengrep", "nightjar.ruby.unsafe-yaml"),
        new("opengrep", "nightjar.php.eval"),
        new("cppcheck", "arrayIndexOutOfBounds"),
        new("cppcheck", "deallocuse"),
        new("trivy", "AWS-0107"),
        new("trivy", "DS-0002"),
        new("trivy-image", "CVE-2022-48174"), // busybox in alpine:3.18.0, fixed upstream: always present
        new("trivy", "KSV-0017"),
    ];

    /// <summary>Engines with no expectation still have to run without errors (e.g. syft).</summary>
    public static async Task<CanaryResult> RunAsync(
        IEnumerable<IEngine> engines, EngineManifest manifest, IProgress<string>? progress, CancellationToken cancellationToken)
    {
        var corpus = ExtractCorpus();
        try
        {
            var report = await new ScanPipeline(engines, manifest).RunAsync(corpus, progress, cancellationToken);
            var ran = report.Engines.Select(e => e.Engine).ToHashSet(StringComparer.OrdinalIgnoreCase);

            var missing = Expectations
                .Where(x => ran.Contains(x.Engine))
                .Where(x => !report.Findings.Any(f =>
                    f.RuleId.Equals(x.RuleId, StringComparison.OrdinalIgnoreCase)
                    && f.Engines.Contains(x.Engine, StringComparer.OrdinalIgnoreCase)))
                .ToList();

            var failed = report.Engines.Where(e => !e.Succeeded).ToList();
            return new CanaryResult(missing.Count == 0 && failed.Count == 0, missing, failed, report);
        }
        finally
        {
            try { Directory.Delete(corpus, recursive: true); } catch (IOException) { }
        }
    }

    /// <summary>Writes the embedded corpus to a temp folder, plus a freshly generated fake token.</summary>
    internal static string ExtractCorpus()
    {
        var root = Directory.CreateTempSubdirectory("nightjar-canary-").FullName;
        var assembly = typeof(CanaryCheck).Assembly;
        const string prefix = "canary/";
        foreach (var name in assembly.GetManifestResourceNames().Where(n => n.StartsWith(prefix, StringComparison.Ordinal)))
        {
            var path = Path.Combine(root, name[prefix.Length..].Replace('/', Path.DirectorySeparatorChar));
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            using var stream = assembly.GetManifestResourceStream(name)!;
            using var file = File.Create(path);
            stream.CopyTo(file);
        }

        // Random each run; never a real credential, and never committed to the repository.
        var token = "ghp_" + Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(40))
            .Replace("+", "").Replace("/", "").Replace("=", "")[..36];
        File.WriteAllText(Path.Combine(root, "src", "settings.env"), $"GITHUB_TOKEN={token}\n");
        return root;
    }
}
