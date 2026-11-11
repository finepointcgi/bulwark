using Nightjar.Core.Engines;
using Nightjar.Core.Findings;
using Nightjar.Engines.Osv;
using Nightjar.Engines.Syft;

namespace Nightjar.Tests;

public class ParserTests
{
    private static string Fixture(string name) => File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Fixtures", name));

    [Fact]
    public void Osv_output_maps_to_findings_with_severity_fixes_and_project_paths()
    {
        var findings = OsvResultParser.Parse(Fixture("osv-scanner.json"), "/Users/me/app", "osv-scanner");

        var finding = Assert.Single(findings);
        Assert.Equal(FindingCategory.Vulnerability, finding.Category);
        Assert.Equal(Severity.High, finding.Severity);
        Assert.Equal("GHSA-35jh-r3h4-6jhm", finding.RuleId);
        Assert.Equal("lodash", finding.Package!.Name);
        Assert.Equal(["4.17.21"], finding.FixedVersions);
        Assert.Equal("web/package-lock.json", finding.Location!.Path);
        Assert.Contains("CVE-2021-23337", finding.Aliases);
    }

    [Fact]
    public void CycloneDx_components_keep_licenses_ecosystem_and_locations()
    {
        var sbom = CycloneDxParser.Parse(Fixture("syft.cdx.json"), "/Users/me/app");

        Assert.Equal(2, sbom.Components.Count);
        var express = sbom.Components.Single(c => c.Package.Name == "express");
        Assert.Equal("npm", express.Package.Ecosystem);
        Assert.Equal(["MIT"], express.Licenses);
        Assert.Equal(["web/package-lock.json"], express.FoundIn);

        var dual = sbom.Components.Single(c => c.Package.Name == "serde");
        Assert.Equal("crates.io", dual.Package.Ecosystem);
        Assert.Equal(["MIT", "Apache-2.0"], dual.Licenses);
    }

    [Theory]
    [InlineData(9.8, Severity.Critical)]
    [InlineData(7.2, Severity.High)]
    [InlineData(5.0, Severity.Medium)]
    [InlineData(2.1, Severity.Low)]
    [InlineData(0, Severity.Unknown)]
    public void Cvss_scores_map_to_severity(double score, Severity expected) =>
        Assert.Equal(expected, OsvResultParser.FromCvss(score));

    [Fact]
    public void Detector_finds_ecosystems_and_skips_vendored_folders()
    {
        var root = Directory.CreateTempSubdirectory("nightjar-detect-").FullName;
        try
        {
            File.WriteAllText(Path.Combine(root, "package-lock.json"), "{}");
            File.WriteAllText(Path.Combine(root, "app.csproj"), "<Project />");
            File.WriteAllText(Path.Combine(root, "Dockerfile"), "FROM alpine");
            Directory.CreateDirectory(Path.Combine(root, "node_modules", "x"));
            File.WriteAllText(Path.Combine(root, "node_modules", "x", "go.mod"), "module x");

            var profile = ProjectDetector.Detect(root);

            Assert.Equal(["NuGet", "npm"], profile.Ecosystems.Order(StringComparer.Ordinal));
            Assert.True(profile.HasContainers);
            Assert.DoesNotContain("Go", profile.Ecosystems);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }
}
