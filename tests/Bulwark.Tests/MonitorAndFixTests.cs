using System.Text.Json.Nodes;
using Bulwark.Core.Findings;
using Bulwark.Core.Fixes;
using Bulwark.Core.Monitoring;
using Bulwark.Core.Sbom;

namespace Bulwark.Tests;

public class MonitorAndFixTests
{
    [Theory]
    [InlineData("4.17.21", "4.17.20", 1)]
    [InlineData("4.17.9", "4.17.10", -1)]
    [InlineData("1.0.0", "1.0.0-rc1", 1)]
    [InlineData("v2.0", "2.0.0", 0)]
    [InlineData("6.0.1", "6.0", 1)]
    public void Versions_compare_numerically(string a, string b, int expected) =>
        Assert.Equal(expected, Math.Sign(FixPlanner.Compare(a, b)));

    [Fact]
    public void Planner_picks_smallest_version_that_fixes_every_advisory_on_a_package()
    {
        Finding[] findings =
        [
            Vuln("A", "lodash", "4.17.20", Severity.High, "4.17.21"),
            Vuln("B", "lodash", "4.17.20", Severity.Medium, "4.17.23", "5.0.0"),
            Vuln("C", "lodash", "4.17.20", Severity.Low, "3.0.0"),            // older than installed: ignored
            Vuln("D", "left-pad", "1.0.0", Severity.Critical),                  // nothing published yet
            Vuln("E", "minimist", "1.2.0", Severity.High, "1.2.6") with { Triage = TriageState.AcceptedRisk },
        ];

        var plan = FixPlanner.Plan(findings);

        var fix = Assert.Single(plan.Fixes);
        Assert.Equal(("lodash", "4.17.23"), (fix.Package.Name, fix.TargetVersion));
        Assert.Equal(Severity.High, fix.WorstSeverity);
        Assert.Equal(["A", "B", "C"], fix.Advisories);
        Assert.Contains(plan.Unfixable, u => u.Finding.RuleId == "D");
        Assert.Contains(plan.Unfixable, u => u.Finding.RuleId == "C"); // reported, but does not block the upgrade
    }

    [Fact]
    public void Osv_record_maps_to_a_finding_that_dedupes_with_scanner_results()
    {
        var component = new SbomComponent(new PackageRef("lodash", "4.17.20", "npm", "pkg:npm/lodash@4.17.20"), [], ["package-lock.json"]);
        var vuln = JsonNode.Parse("""
            {"id":"GHSA-35jh-r3h4-6jhm","summary":"Command Injection in lodash","aliases":["CVE-2021-23337"],
             "affected":[{"package":{"ecosystem":"npm","name":"lodash"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"4.17.21"}]}]}],
             "database_specific":{"severity":"HIGH"},"references":[{"url":"https://example.invalid/a"}]}
            """)!.AsObject();

        var finding = AdvisoryMonitor.ToFinding(component, "GHSA-35jh-r3h4-6jhm", vuln);

        Assert.Equal(Severity.High, finding.Severity);
        Assert.Equal(["4.17.21"], finding.FixedVersions);
        Assert.Equal(Fingerprint.ForVulnerability(new PackageRef("lodash", "4.17.20", "npm"), "GHSA-35jh-r3h4-6jhm", ["CVE-2021-23337"]), finding.Id);
    }

    [Fact]
    public void Saved_cyclonedx_sbom_reads_back_packages_and_locations()
    {
        var sbom = SbomReader.Read(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Fixtures", "syft.cdx.json")));

        Assert.Equal(2, sbom.Count);
        Assert.Equal("pkg:npm/express@4.19.2", sbom[0].Package.Purl);
        Assert.Equal(["web/package-lock.json"], sbom[0].FoundIn);
        Assert.Equal("crates.io", sbom[1].Package.Ecosystem);
    }

    [Fact]
    public void Alert_text_lists_new_advisories_per_project()
    {
        var text = WebhookNotifier.Format([new MonitorResult("/repos/shop", 120, [Vuln("CVE-2026-1", "lodash", "4.17.20", Severity.Critical, "4.17.30")])]);

        Assert.StartsWith("Bulwark: 1 new advisory affect", text);
        Assert.Contains("shop (/repos/shop)", text);
        Assert.Contains("CRITICAL CVE-2026-1: lodash@4.17.20 (fixed in 4.17.30)", text);
    }

    private static Finding Vuln(string id, string name, string version, Severity severity, params string[] fixes) => new()
    {
        Id = $"{name}-{id}", Category = FindingCategory.Vulnerability, Severity = severity, RuleId = id, Title = id,
        Package = new PackageRef(name, version, "npm"), Location = new SourceLocation("package-lock.json"), FixedVersions = fixes,
    };
}
