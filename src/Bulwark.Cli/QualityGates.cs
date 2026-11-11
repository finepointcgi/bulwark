using System.Globalization;
using Bulwark.Core.Quality;
using Bulwark.Core.Reports;

namespace Bulwark.Cli;

/// <summary>Optional metric gates: --min-coverage 80, --max-duplication 5 (percent).</summary>
internal static class QualityGates
{
    public static int Check(ScanReport report, Options options)
    {
        var failed = false;
        var metrics = report.Metrics ?? new Dictionary<string, double>();

        if (options.Value("min-coverage") is { } min)
        {
            var threshold = double.Parse(min, CultureInfo.InvariantCulture);
            if (!metrics.TryGetValue(MetricNames.LineCoverage, out var coverage))
            {
                Console.Error.WriteLine("Coverage gate FAILED: no coverage report found (cobertura XML or lcov.info). Run your tests with coverage before scanning.");
                failed = true;
            }
            else if (coverage < threshold)
            {
                Console.Error.WriteLine($"Coverage gate FAILED: {coverage:0.0}% line coverage, need {threshold:0.#}%.");
                failed = true;
            }
            else
            {
                Console.Error.WriteLine($"Coverage gate passed: {coverage:0.0}% ≥ {threshold:0.#}%.");
            }
        }

        if (options.Value("max-duplication") is { } max && metrics.TryGetValue(MetricNames.DuplicationRate, out var duplication))
        {
            var threshold = double.Parse(max, CultureInfo.InvariantCulture);
            if (duplication > threshold)
            {
                Console.Error.WriteLine($"Duplication gate FAILED: {duplication:0.0}% duplicated code, limit {threshold:0.#}%.");
                failed = true;
            }
        }

        return failed ? 1 : 0;
    }

    public static string Summary(ScanReport report) =>
        report.Metrics is not { Count: > 0 } metrics
            ? ""
            : string.Join(" · ", metrics.OrderBy(m => m.Key, StringComparer.Ordinal).Select(m => $"{MetricNames.Label(m.Key)} {MetricNames.Format(m.Key, m.Value)}"));
}
