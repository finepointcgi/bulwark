using System.Globalization;
using System.Xml.Linq;

namespace Bulwark.Core.Quality;

/// <summary>Metric keys stored in <see cref="Reports.ScanReport.Metrics"/>.</summary>
public static class MetricNames
{
    public const string LineCoverage = "coverage.lines";
    public const string DuplicationRate = "duplication.rate";
    public const string Functions = "complexity.functions";
    public const string AverageComplexity = "complexity.average";
    public const string MaxComplexity = "complexity.max";
    public const string ComplexFunctions = "complexity.over-threshold";

    public static string Label(string key) => key switch
    {
        LineCoverage => "Line coverage",
        DuplicationRate => "Duplicated code",
        Functions => "Functions",
        AverageComplexity => "Average complexity",
        MaxComplexity => "Highest complexity",
        ComplexFunctions => "Overly complex functions",
        _ => key,
    };

    public static string Format(string key, double value) => key switch
    {
        LineCoverage or DuplicationRate => value.ToString("0.0", CultureInfo.InvariantCulture) + "%",
        AverageComplexity => value.ToString("0.0", CultureInfo.InvariantCulture),
        _ => value.ToString("0", CultureInfo.InvariantCulture),
    };
}

public sealed record CoverageResult(double LineRate, int LinesCovered, int LinesValid, IReadOnlyList<string> Files);

/// <summary>
/// Reads test coverage reports the project already produces (Cobertura XML from coverlet,
/// pytest-cov, Jest, JaCoCo-converted...; LCOV from Jest, c8, gcov) and combines them.
/// Bulwark never runs the tests itself.
/// </summary>
public static class CoverageReader
{
    private static readonly string[] CoberturaNames = ["coverage.cobertura.xml", "cobertura.xml", "coverage.xml", "cobertura-coverage.xml"];
    private static readonly string[] LcovNames = ["lcov.info", "coverage.lcov"];

    public static CoverageResult? Find(string root, IEnumerable<string> files)
    {
        var covered = 0;
        var valid = 0;
        var used = new List<string>();
        foreach (var file in files)
        {
            var name = Path.GetFileName(file);
            (int Covered, int Valid)? counts = null;
            try
            {
                if (CoberturaNames.Contains(name, StringComparer.OrdinalIgnoreCase))
                {
                    counts = Cobertura(File.ReadAllText(file));
                }
                else if (LcovNames.Contains(name, StringComparer.OrdinalIgnoreCase))
                {
                    counts = Lcov(File.ReadAllLines(file));
                }
            }
            catch (Exception e) when (e is System.Xml.XmlException or IOException or FormatException)
            {
                continue; // A broken report should not fail the scan.
            }

            if (counts is { Valid: > 0 } c)
            {
                covered += c.Covered;
                valid += c.Valid;
                used.Add(Path.GetRelativePath(root, file).Replace('\\', '/'));
            }
        }

        return valid == 0 ? null : new CoverageResult(100.0 * covered / valid, covered, valid, used);
    }

    internal static (int Covered, int Valid)? Cobertura(string xml)
    {
        var root = XDocument.Parse(xml).Root;
        if (root is null || root.Name.LocalName != "coverage")
        {
            return null;
        }

        if (root.Attribute("lines-covered") is { } c && root.Attribute("lines-valid") is { } v)
        {
            return (int.Parse(c.Value, CultureInfo.InvariantCulture), int.Parse(v.Value, CultureInfo.InvariantCulture));
        }

        // Older writers only give per-line hits.
        var lines = root.Descendants("line").ToList();
        return (lines.Count(l => (int?)l.Attribute("hits") > 0), lines.Count);
    }

    internal static (int Covered, int Valid) Lcov(IEnumerable<string> lines)
    {
        int covered = 0, valid = 0;
        foreach (var line in lines)
        {
            if (line.StartsWith("LH:", StringComparison.Ordinal)) { covered += int.Parse(line[3..], CultureInfo.InvariantCulture); }
            else if (line.StartsWith("LF:", StringComparison.Ordinal)) { valid += int.Parse(line[3..], CultureInfo.InvariantCulture); }
        }

        return (covered, valid);
    }
}
