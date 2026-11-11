using System.Diagnostics;
using Nightjar.Core.Engines;
using Nightjar.Core.Findings;
using Nightjar.Engines.Execution;
using Nightjar.Engines.Sarif;

namespace Nightjar.Engines.Cppcheck;

/// <summary>
/// C/C++ defects with cppcheck: memory safety (out-of-bounds, use-after-free, double free),
/// uninitialized data, null dereferences, leaks. Needs no build system or compile database,
/// so it works on any checkout. Runs only when C or C++ sources are present.
/// </summary>
public sealed class CppcheckEngine(ToolRunner runner) : IEngine
{
    private const string ReportFile = "cppcheck.sarif";

    /// <summary>
    /// cppcheck scores every error 9.9, which would make a leak "critical". Grade by defect class:
    /// memory corruption is exploitable, a leak usually is not.
    /// </summary>
    private static readonly Dictionary<string, Severity> SeverityByRule = new(StringComparer.Ordinal)
    {
        ["arrayIndexOutOfBounds"] = Severity.Critical,
        ["arrayIndexOutOfBoundsCond"] = Severity.Critical,
        ["bufferAccessOutOfBounds"] = Severity.Critical,
        ["outOfBounds"] = Severity.Critical,
        ["negativeIndex"] = Severity.Critical,
        ["pointerOutOfBounds"] = Severity.Critical,
        ["deallocuse"] = Severity.Critical,
        ["doubleFree"] = Severity.Critical,
        ["invalidFree"] = Severity.Critical,
        ["mismatchAllocDealloc"] = Severity.High,
        ["uninitvar"] = Severity.High,
        ["uninitdata"] = Severity.High,
        ["nullPointer"] = Severity.High,
        ["danglingLifetime"] = Severity.High,
        ["returnDanglingLifetime"] = Severity.High,
        ["invalidLifetime"] = Severity.High,
        ["integerOverflow"] = Severity.High,
        ["invalidFunctionArg"] = Severity.Medium,
        ["memleak"] = Severity.Medium,
        ["resourceLeak"] = Severity.Medium,
        ["leakReturnValNotUsed"] = Severity.Medium,
        ["nullPointerOutOfMemory"] = Severity.Low,
        ["nullPointerOutOfResources"] = Severity.Low,
    };

    public string Name => "cppcheck";
    public int Order => 45;

    public bool AppliesTo(ScanContext context) =>
        context.Profile.Languages.Contains("c") || context.Profile.Languages.Contains("cpp");

    public async Task<EngineResult> RunAsync(ScanContext context, CancellationToken cancellationToken)
    {
        var stopwatch = Stopwatch.StartNew();
        var output = await runner.RunAsync(
            Name,
            ["--enable=warning,portability", "--quiet", "--suppress=missingIncludeSystem", "--suppress=missingInclude",
                "-j", Math.Clamp(Environment.ProcessorCount, 1, 8).ToString(System.Globalization.CultureInfo.InvariantCulture),
                "-i", $"{ToolRunner.SourceToken}/node_modules", "-i", $"{ToolRunner.SourceToken}/.git",
                "--output-format=sarif", $"--output-file={ToolRunner.WorkToken}/{ReportFile}", ToolRunner.SourceToken],
            context.RootPath, context.WorkDirectory, TimeSpan.FromMinutes(30), cancellationToken);

        var reportPath = Path.Combine(context.WorkDirectory, ReportFile);
        if (output.ExitCode != 0 || !File.Exists(reportPath))
        {
            return EngineResult.Failed(Name, $"cppcheck exited {output.ExitCode}: {output.StandardError.Trim()}", stopwatch.Elapsed);
        }

        var findings = SarifParser
            .Parse(await File.ReadAllTextAsync(reportPath, cancellationToken), context.RootPath, Name, FindingCategory.Code)
            .Select(Grade)
            .ToList();
        return new EngineResult(Name, findings, stopwatch.Elapsed);
    }

    public static Finding Grade(Finding finding) =>
        SeverityByRule.TryGetValue(finding.RuleId, out var severity)
            ? finding with { Severity = severity }
            : finding with { Severity = finding.Severity >= Severity.High ? Severity.Medium : finding.Severity };
}
