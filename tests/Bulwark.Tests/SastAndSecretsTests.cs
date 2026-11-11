using Bulwark.Core.Findings;
using Bulwark.Core.Reports;
using Bulwark.Engines.Gitleaks;
using Bulwark.Engines.Opengrep;
using Bulwark.Engines.Sarif;

namespace Bulwark.Tests;

public class SastAndSecretsTests
{
    private static string Fixture(string name) => File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Fixtures", name));

    [Fact]
    public void Opengrep_sarif_maps_to_code_findings_with_clean_ids_and_paths()
    {
        var findings = SarifParser.Parse(Fixture("opengrep.sarif"), "/Users/me/app", "opengrep", FindingCategory.Code, OpengrepEngine.NormalizeRuleId);

        Assert.Equal(19, findings.Count);
        Assert.All(findings, f => Assert.StartsWith("bulwark.", f.RuleId));
        Assert.All(findings, f => Assert.Equal(FindingCategory.Code, f.Category));

        var sql = findings.First(f => f.RuleId == "bulwark.csharp.sql-injection-concat");
        Assert.Equal("Db.cs", sql.Location!.Path); // container mount /src/Db.cs → project-relative
        Assert.Equal(8, sql.Location.StartLine);
        Assert.Equal(Severity.High, sql.Severity);

        Assert.Equal(Severity.Medium, findings.First(f => f.RuleId == "bulwark.csharp.weak-hash").Severity);
        Assert.Equal(findings.Count, findings.Select(f => f.Id).Distinct().Count());
    }

    [Theory]
    [InlineData("rules.bulwark.go.sql-injection", "bulwark.go.sql-injection")]
    [InlineData("work.rules.bulwark.js.eval", "bulwark.js.eval")]
    [InlineData("work.rules.custom0.acme.no-debug", "acme.no-debug")]
    [InlineData("tmp.bulwark-x.rules.custom12.r", "r")]
    [InlineData("plain-id", "plain-id")]
    public void Rule_ids_lose_the_config_folder_prefix(string raw, string expected) =>
        Assert.Equal(expected, OpengrepEngine.NormalizeRuleId(raw));

    [Fact]
    public void Rule_pack_is_embedded()
    {
        var resources = typeof(OpengrepEngine).Assembly.GetManifestResourceNames();
        Assert.Contains("rules/csharp.yaml", resources);
        Assert.Contains("rules/python.yaml", resources);
    }

    [Fact]
    public void Gitleaks_findings_never_contain_the_secret()
    {
        const string secret = "ghp_FAKEfakeFAKEfakeFAKEfakeFAKEfake1234";
        var json = $$"""
            [{
              "RuleID": "github-pat", "Description": "GitHub Personal Access Token",
              "StartLine": 3, "EndLine": 3, "Match": "TOKEN={{secret}}", "Secret": "{{secret}}",
              "File": "/src/config/.env", "Fingerprint": "/src/config/.env:github-pat:3"
            }]
            """;

        var finding = Assert.Single(GitleaksParser.Parse(json, "/Users/me/app", "gitleaks"));
        var report = new ScanReport
        {
            Project = "/Users/me/app", StartedAt = DateTimeOffset.UnixEpoch, Seconds = 0, ManifestSequence = 0,
            Engines = [], Findings = [finding],
        };

        Assert.Equal(FindingCategory.Secret, finding.Category);
        Assert.Equal("config/.env", finding.Location!.Path);
        Assert.DoesNotContain(secret, report.ToJson());
        Assert.DoesNotContain(secret, SarifWriter.Write(report, "test"));
        Assert.Contains("ghp_****", finding.Description);
    }

    [Fact]
    public void Same_secret_on_a_different_line_keeps_its_id_but_a_rotated_one_does_not()
    {
        static string Leak(string secret, int line) =>
            $$"""[{"RuleID":"github-pat","StartLine":{{line}},"Secret":"{{secret}}","File":"/src/.env"}]""";

        var original = GitleaksParser.Parse(Leak("ghp_aaaaaaaaaaaaaaaa", 1), "/x", "gitleaks")[0].Id;
        var moved = GitleaksParser.Parse(Leak("ghp_aaaaaaaaaaaaaaaa", 9), "/x", "gitleaks")[0].Id;
        var rotated = GitleaksParser.Parse(Leak("ghp_bbbbbbbbbbbbbbbb", 1), "/x", "gitleaks")[0].Id;

        Assert.Equal(original, moved);
        Assert.NotEqual(original, rotated);
    }
}
