using Nightjar.Core.Quality;
using Nightjar.Engines.Lizard;

namespace Nightjar.Tests;

public class QualityTests
{
    [Fact]
    public void Lizard_csv_parses_functions_with_project_paths()
    {
        const string csv = """
            27,9,170,1,27,"calc_a@1-27@/src/dup_a.py","/src/dup_a.py","calc_a","calc_a( values )",1,27
            51,25,202,1,51,"tangled@1-51@/src/complex.py","/src/complex.py","tangled","tangled( x )",1,51
            """;

        var functions = LizardEngine.ParseCsv(csv, "/Users/me/app");

        Assert.Equal(2, functions.Count);
        Assert.Equal(new LizardEngine.FunctionInfo("complex.py", "tangled", 1, 25, 51), functions[1]);
    }

    [Fact]
    public void Lizard_duplicate_report_parses_blocks_and_rate()
    {
        const string text = """
            Duplicates
            ===================================
            Duplicate block:
            --------------------------
            /src/dup_a.py:1 ~ 22
            /src/dup_b.py:1 ~ 22
            ^^^^^^^^^^^^^^^^^^^^^^^^^^

            Total duplicate rate: 50.64%
            Total unique rate: 69.70%
            """;

        var (blocks, rate) = LizardEngine.ParseDuplicates(text, "/Users/me/app");

        var block = Assert.Single(blocks);
        Assert.Equal([("dup_a.py", 1, 22), ("dup_b.py", 1, 22)], block.Copies);
        Assert.Equal(50.64, rate);
    }

    [Fact]
    public void Cobertura_uses_totals_and_lcov_sums_records()
    {
        Assert.Equal((80, 100), CoverageReader.Cobertura("""<coverage line-rate="0.8" lines-covered="80" lines-valid="100"><packages/></coverage>"""));
        Assert.Equal((1, 2), CoverageReader.Cobertura("""<coverage><packages><package><classes><class><lines><line number="1" hits="3"/><line number="2" hits="0"/></lines></class></classes></package></packages></coverage>"""));
        Assert.Equal((15, 20), CoverageReader.Lcov(["SF:a.js", "LF:10", "LH:7", "end_of_record", "SF:b.js", "LF:10", "LH:8", "end_of_record"]));
    }

    [Fact]
    public void Coverage_reports_in_a_project_are_combined()
    {
        var root = Directory.CreateTempSubdirectory("nightjar-cov-").FullName;
        try
        {
            Directory.CreateDirectory(Path.Combine(root, "web", "coverage"));
            File.WriteAllText(Path.Combine(root, "web", "coverage", "lcov.info"), "SF:a.js\nLF:50\nLH:25\nend_of_record\n");
            File.WriteAllText(Path.Combine(root, "coverage.cobertura.xml"), """<coverage lines-covered="75" lines-valid="50"/>""".Replace("75", "45"));

            var result = CoverageReader.Find(root, Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories));

            Assert.NotNull(result);
            Assert.Equal(70.0, result.LineRate, 3); // (25 + 45) / (50 + 50)
            Assert.Equal(2, result.Files.Count);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Theory]
    [InlineData(MetricNames.LineCoverage, 72.345, "72.3%")]
    [InlineData(MetricNames.AverageComplexity, 3.14159, "3.1")]
    [InlineData(MetricNames.MaxComplexity, 25, "25")]
    public void Metrics_format_for_display(string key, double value, string expected) =>
        Assert.Equal(expected, MetricNames.Format(key, value));
}
