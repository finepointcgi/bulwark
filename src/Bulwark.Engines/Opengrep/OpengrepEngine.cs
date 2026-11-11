using System.Diagnostics;
using Bulwark.Core.Engines;
using Bulwark.Core.Findings;
using Bulwark.Engines.Execution;
using Bulwark.Engines.Sarif;

namespace Bulwark.Engines.Opengrep;

/// <summary>
/// SAST with Opengrep (the open fork of Semgrep) using Bulwark's own Apache-2.0 rule pack,
/// plus any extra rule folders the user passes. Semgrep's registry rules are not used:
/// their license does not allow bundling in a competing tool.
/// </summary>
public sealed class OpengrepEngine(ToolRunner runner, IReadOnlyList<string>? extraRuleDirectories = null) : IEngine
{
    /// <summary>Languages the bundled rule pack covers. Custom rules make the engine run for any language.</summary>
    private static readonly HashSet<string> CoveredLanguages = new(StringComparer.OrdinalIgnoreCase)
    {
        "csharp", "javascript", "typescript", "python", "java", "go", "c", "cpp", "php", "ruby",
    };

    private const string RulesFolder = "rules";
    private const string ReportFile = "opengrep.sarif";

    public string Name => "opengrep";
    public int Order => 40;

    public bool AppliesTo(ScanContext context) =>
        context.Profile.Languages.Any(CoveredLanguages.Contains) || extraRuleDirectories is { Count: > 0 };

    public async Task<EngineResult> RunAsync(ScanContext context, CancellationToken cancellationToken)
    {
        var stopwatch = Stopwatch.StartNew();
        var rulesPath = Path.Combine(context.WorkDirectory, RulesFolder);
        var ruleCount = WriteRules(rulesPath);

        var output = await runner.RunAsync(
            Name,
            ["scan", "--config", $"{ToolRunner.WorkToken}/{RulesFolder}", "--sarif", "--output", $"{ToolRunner.WorkToken}/{ReportFile}",
                "--quiet", "--disable-version-check", ToolRunner.SourceToken],
            context.RootPath, context.WorkDirectory, TimeSpan.FromMinutes(20), cancellationToken);

        var reportPath = Path.Combine(context.WorkDirectory, ReportFile);
        if (output.ExitCode is not (0 or 1) || !File.Exists(reportPath))
        {
            var hint = output.StandardError.Contains("pull access denied", StringComparison.OrdinalIgnoreCase)
                || output.StandardError.Contains("Unable to find image", StringComparison.OrdinalIgnoreCase)
                ? " Build the engine image first: docker build -t bulwark-engines/opengrep:v1.33.1 engines/opengrep"
                : "";
            return EngineResult.Failed(Name, $"opengrep exited {output.ExitCode}: {LastLines(output.StandardError)}{hint}", stopwatch.Elapsed);
        }

        var findings = SarifParser.Parse(
            await File.ReadAllTextAsync(reportPath, cancellationToken),
            context.RootPath, Name, FindingCategory.Code, NormalizeRuleId);

        return ruleCount == 0
            ? EngineResult.Failed(Name, "no rules were loaded", stopwatch.Elapsed)
            : new EngineResult(Name, findings, stopwatch.Elapsed);
    }

    /// <summary>
    /// Opengrep prefixes rule ids with the config folder path ("work.rules.custom.my-rule").
    /// Strip it so ids match what the rule author wrote and stay stable across machines.
    /// </summary>
    public static string NormalizeRuleId(string id)
    {
        var marker = $"{RulesFolder}.";
        var index = id.IndexOf(marker, StringComparison.Ordinal);
        if (index < 0)
        {
            return id;
        }

        var rest = id[(index + marker.Length)..];
        return rest.StartsWith("custom", StringComparison.Ordinal) && rest.IndexOf('.', 6) is var dot and > 0
            ? rest[(dot + 1)..]
            : rest;
    }

    /// <summary>Writes the embedded rule pack and copies user rule folders into the work directory.</summary>
    private int WriteRules(string rulesPath)
    {
        Directory.CreateDirectory(rulesPath);
        var count = 0;
        var assembly = typeof(OpengrepEngine).Assembly;
        foreach (var resource in assembly.GetManifestResourceNames().Where(n => n.StartsWith("rules/", StringComparison.Ordinal)))
        {
            using var stream = assembly.GetManifestResourceStream(resource)!;
            using var file = File.Create(Path.Combine(rulesPath, Path.GetFileName(resource)));
            stream.CopyTo(file);
            count++;
        }

        var index = 0;
        foreach (var directory in extraRuleDirectories ?? [])
        {
            var target = Path.Combine(rulesPath, $"custom{index++}");
            Directory.CreateDirectory(target);
            foreach (var rule in Directory.EnumerateFiles(directory, "*.y*ml", SearchOption.AllDirectories))
            {
                File.Copy(rule, Path.Combine(target, $"{count++}-{Path.GetFileName(rule)}"));
            }
        }

        return count;
    }

    private static string LastLines(string text) =>
        string.Join(" | ", text.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).TakeLast(3));
}
