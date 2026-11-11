using Bulwark.Core.Findings;
using Bulwark.Core.Policy;
using Bulwark.Core.Sbom;

namespace Bulwark.Tests;

public class FingerprintTests
{
    private static readonly PackageRef Lodash = new("lodash", "4.17.20", "npm");

    [Fact]
    public void Prefers_cve_so_engines_using_different_ids_agree()
    {
        var fromOsv = Fingerprint.ForVulnerability(Lodash, "GHSA-35jh-r3h4-6jhm", ["CVE-2021-23337"]);
        var fromOther = Fingerprint.ForVulnerability(Lodash, "CVE-2021-23337", ["GHSA-35jh-r3h4-6jhm"]);
        Assert.Equal(fromOsv, fromOther);
    }

    [Fact]
    public void Different_versions_get_different_ids()
    {
        var a = Fingerprint.ForVulnerability(Lodash, "CVE-2021-23337", []);
        var b = Fingerprint.ForVulnerability(Lodash with { Version = "4.17.21" }, "CVE-2021-23337", []);
        Assert.NotEqual(a, b);
    }

    [Fact]
    public void Code_fingerprint_ignores_line_moves_and_whitespace()
    {
        var before = Fingerprint.ForCode("sql-injection", "./src/Db.cs", "query(  \"SELECT \" + id )", 10);
        var after = Fingerprint.ForCode("sql-injection", "src/Db.cs", "query( \"SELECT \" + id )", 42);
        Assert.Equal(before, after);
    }
}

public class FindingMergerTests
{
    [Fact]
    public void Merges_duplicates_keeping_worst_severity_and_all_engines()
    {
        var a = Make("id1", Severity.Medium, "osv-scanner", fixes: ["1.2.3"]);
        var b = Make("id1", Severity.High, "grype", fixes: ["1.2.3", "2.0.0"]);
        var c = Make("id2", Severity.Low, "osv-scanner");

        var merged = FindingMerger.Merge([a, b, c]);

        Assert.Equal(2, merged.Count);
        var first = merged[0];
        Assert.Equal(Severity.High, first.Severity);
        Assert.Equal(["osv-scanner", "grype"], first.Engines);
        Assert.Equal(["1.2.3", "2.0.0"], first.FixedVersions);
    }

    private static Finding Make(string id, Severity severity, string engine, string[]? fixes = null) => new()
    {
        Id = id, Category = FindingCategory.Vulnerability, Severity = severity, RuleId = "CVE-1", Title = "t",
        Engines = [engine], FixedVersions = fixes ?? [],
    };
}

public class PolicyTests
{
    [Fact]
    public void License_policy_flags_denied_review_and_unknown()
    {
        var sbom = new SoftwareBillOfMaterials(
        [
            Component("ok", "MIT"),
            Component("copyleft", "AGPL-3.0-only"),
            Component("weak", "LGPL-2.1-only"),
            Component("mystery"),
        ], "{}");

        var findings = new LicensePolicy().Evaluate(sbom).ToList();

        Assert.Equal(3, findings.Count);
        Assert.Contains(findings, f => f.Package!.Name == "copyleft" && f.Severity == Severity.High);
        Assert.Contains(findings, f => f.Package!.Name == "weak" && f.Severity == Severity.Medium);
        Assert.Contains(findings, f => f.Package!.Name == "mystery" && f.Severity == Severity.Low);
    }

    [Fact]
    public void Quality_gate_ignores_triaged_findings()
    {
        Finding high = new() { Id = "1", Category = FindingCategory.Vulnerability, Severity = Severity.High, RuleId = "r", Title = "t" };
        var gate = new QualityGate(Severity.High);

        Assert.False(gate.Evaluate([high]).Passed);
        Assert.True(gate.Evaluate([high with { Triage = TriageState.FalsePositive }]).Passed);
        Assert.True(gate.Evaluate([high with { Severity = Severity.Medium }]).Passed);
    }

    private static SbomComponent Component(string name, params string[] licenses) =>
        new(new PackageRef(name, "1.0.0", "npm"), licenses, ["package-lock.json"]);
}
