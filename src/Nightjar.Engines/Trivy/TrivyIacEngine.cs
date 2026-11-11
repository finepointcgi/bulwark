using System.Diagnostics;
using Nightjar.Core.Engines;
using Nightjar.Core.Findings;
using Nightjar.Engines.Execution;
using Nightjar.Engines.Sarif;

namespace Nightjar.Engines.Trivy;

/// <summary>
/// Infrastructure-as-code misconfigurations with Trivy: Terraform, CloudFormation, Kubernetes,
/// Helm, Dockerfiles, Azure ARM and Ansible. Uses the checks built into the pinned Trivy binary
/// (<c>--skip-check-update</c>), so results only change when the manifest bumps Trivy and scans
/// work offline.
/// </summary>
public sealed class TrivyIacEngine(ToolRunner runner) : IEngine
{
    private const string ReportFile = "trivy-config.sarif";

    public string Name => "trivy";
    public int Order => 50;

    public bool AppliesTo(ScanContext context) =>
        context.Profile.HasInfrastructureAsCode || context.Profile.HasContainers || IacDetector.HasIacFiles(context.RootPath);

    public async Task<EngineResult> RunAsync(ScanContext context, CancellationToken cancellationToken)
    {
        var stopwatch = Stopwatch.StartNew();
        var output = await runner.RunAsync(
            Name,
            ["config", "--skip-check-update", "--format", "sarif", "--output", $"{ToolRunner.WorkToken}/{ReportFile}",
                "--quiet", "--exit-code", "0", ToolRunner.SourceToken],
            context.RootPath, context.WorkDirectory, TimeSpan.FromMinutes(15), cancellationToken,
            new Dictionary<string, string> { ["HOME"] = "/tmp" });

        var reportPath = Path.Combine(context.WorkDirectory, ReportFile);
        if (output.ExitCode != 0 || !File.Exists(reportPath))
        {
            return EngineResult.Failed(Name, $"trivy exited {output.ExitCode}: {output.StandardError.Trim()}", stopwatch.Elapsed);
        }

        var findings = SarifParser
            .Parse(await File.ReadAllTextAsync(reportPath, cancellationToken), context.RootPath, Name, FindingCategory.Infrastructure)
            .Select(Clean)
            .ToList();

        return new EngineResult(Name, findings, stopwatch.Elapsed);
    }

    /// <summary>
    /// Trivy's SARIF message is a multi-line block ("Artifact: ...\nType: ...\nMessage: ...").
    /// Keep just the specific message, and put the file in the title so rows are distinguishable.
    /// </summary>
    public static Finding Clean(Finding finding)
    {
        var message = finding.Description?
            .Split('\n')
            .Select(line => line.Trim())
            .FirstOrDefault(line => line.StartsWith("Message:", StringComparison.Ordinal))?["Message:".Length..]
            .Trim();

        return finding with
        {
            Description = message ?? finding.Description,
            Title = finding.Location?.Path is { } path ? $"{finding.Title} in {path}" : finding.Title,
        };
    }
}

/// <summary>
/// Finds IaC that file extensions alone don't reveal: Kubernetes manifests, CloudFormation and
/// ARM templates are plain YAML/JSON, so peek at the start of each candidate file.
/// </summary>
public static class IacDetector
{
    private const int PeekBytes = 4096;
    private const long MaxFileSize = 2 * 1024 * 1024;

    public static bool HasIacFiles(string root)
    {
        foreach (var file in ProjectDetector.EnumerateFiles(root))
        {
            var name = Path.GetFileName(file);
            if (name is "Chart.yaml" or "docker-compose.yml" or "docker-compose.yaml" or "compose.yaml")
            {
                return true;
            }

            var extension = Path.GetExtension(file).ToLowerInvariant();
            if (extension is ".tf" or ".tfvars" or ".hcl")
            {
                return true;
            }

            if (extension is ".yaml" or ".yml" or ".json" && LooksLikeIac(file))
            {
                return true;
            }
        }

        return false;
    }

    internal static bool LooksLikeIac(string file)
    {
        try
        {
            var info = new FileInfo(file);
            if (info.Length is 0 or > MaxFileSize)
            {
                return false;
            }

            using var reader = new StreamReader(file);
            var buffer = new char[PeekBytes];
            var head = new string(buffer, 0, reader.ReadBlock(buffer, 0, buffer.Length));

            var kubernetes = head.Contains("apiVersion", StringComparison.Ordinal) && head.Contains("kind", StringComparison.Ordinal);
            var cloudFormation = head.Contains("AWSTemplateFormatVersion", StringComparison.Ordinal)
                || head.Contains("Type: AWS::", StringComparison.Ordinal) || head.Contains("\"Type\": \"AWS::", StringComparison.Ordinal);
            var arm = head.Contains("schema.management.azure.com", StringComparison.OrdinalIgnoreCase);
            return kubernetes || cloudFormation || arm;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }
}
