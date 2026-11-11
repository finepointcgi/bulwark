using System.Text.Json.Nodes;
using Bulwark.Core.Findings;
using Bulwark.Core.Sbom;

namespace Bulwark.Tests;

public sealed class SbomExportTests
{
    private const string Cdx = """
        {"bomFormat":"CycloneDX","specVersion":"1.5","components":[
          {"type":"library","bom-ref":"a","name":"lodash","version":"4.17.20","purl":"pkg:npm/lodash@4.17.20"}]}
        """;

    private static SoftwareBillOfMaterials Sbom() => new(
        [new SbomComponent(new PackageRef("lodash", "4.17.20", "npm", "pkg:npm/lodash@4.17.20"), ["MIT"], ["package.json"])], Cdx);

    private static Finding Vuln(TriageState state, Reachability reach = Reachability.Unknown) => new()
    {
        Id = "f1", Category = FindingCategory.Vulnerability, Severity = Severity.High, RuleId = "GHSA-x", Title = "Prototype pollution",
        Package = new PackageRef("lodash", "4.17.20", "npm", "pkg:npm/lodash@4.17.20"), Triage = state, Reachability = reach,
    };

    [Theory]
    [InlineData(TriageState.New, "in_triage")]
    [InlineData(TriageState.FalsePositive, "false_positive")]
    [InlineData(TriageState.AcceptedRisk, "exploitable")]
    [InlineData(TriageState.Fixed, "resolved")]
    public void Vex_state_follows_triage(TriageState triage, string expected)
    {
        var doc = JsonNode.Parse(SbomExporter.CycloneDxWithVex(Sbom(), [Vuln(triage)]))!;
        var vuln = doc["vulnerabilities"]![0]!;
        Assert.Equal(expected, (string?)vuln["analysis"]!["state"]);
        Assert.Equal("a", (string?)vuln["affects"]![0]!["ref"]);
        Assert.Equal("GHSA-x", (string?)vuln["id"]);
    }

    [Fact]
    public void Unimported_packages_are_noted_but_never_declared_not_affected()
    {
        var doc = JsonNode.Parse(SbomExporter.CycloneDxWithVex(Sbom(), [Vuln(TriageState.New, Reachability.NotImported)]))!;
        var analysis = doc["vulnerabilities"]![0]!["analysis"]!;
        Assert.Equal("in_triage", (string?)analysis["state"]);
        Assert.Contains("Not imported", (string?)analysis["detail"]);
    }

    [Fact]
    public void Spdx_lists_packages_with_purls_and_licenses()
    {
        var doc = JsonNode.Parse(SbomExporter.Spdx(Sbom(), "demo", DateTimeOffset.UnixEpoch))!;
        Assert.Equal("SPDX-2.3", (string?)doc["spdxVersion"]);
        var package = doc["packages"]![0]!;
        Assert.Equal("lodash", (string?)package["name"]);
        Assert.Equal("MIT", (string?)package["licenseDeclared"]);
        Assert.Equal("pkg:npm/lodash@4.17.20", (string?)package["externalRefs"]![0]!["referenceLocator"]);
        Assert.Equal("DESCRIBES", (string?)doc["relationships"]![0]!["relationshipType"]);
    }
}

public sealed class SbomDuplicateTests
{
    [Fact]
    public void Duplicate_components_do_not_break_vex_export()
    {
        const string cdx = """
            {"components":[{"bom-ref":"a","name":"x","version":"1","purl":"pkg:npm/x@1"},{"bom-ref":"b","name":"x","version":"1","purl":"pkg:npm/x@1"}]}
            """;
        var sbom = new Bulwark.Core.Sbom.SoftwareBillOfMaterials([], cdx);
        var json = Bulwark.Core.Sbom.SbomExporter.CycloneDxWithVex(sbom, []);
        Assert.Contains("vulnerabilities", json);
    }
}
