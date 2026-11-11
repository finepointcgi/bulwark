using Nightjar.Core.Findings;
using Nightjar.Engines.Sarif;
using Nightjar.Engines.Trivy;

namespace Nightjar.Tests;

public class IacTests
{
    private static IReadOnlyList<Finding> Parse() =>
        SarifParser.Parse(
                File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Fixtures", "trivy-config.sarif")),
                "/Users/me/app", "trivy", FindingCategory.Infrastructure)
            .Select(TrivyIacEngine.Clean)
            .ToList();

    [Fact]
    public void Trivy_sarif_maps_to_infrastructure_findings()
    {
        var findings = Parse();

        Assert.Equal(32, findings.Count);
        Assert.All(findings, f => Assert.Equal(FindingCategory.Infrastructure, f.Category));
        Assert.Equal(findings.Count, findings.Select(f => f.Id).Distinct().Count());
        Assert.Contains(findings, f => f.Location!.Path == "infra/main.tf");
        Assert.Contains(findings, f => f.Location!.Path == "k8s/pod.yaml");
    }

    [Theory]
    [InlineData("DS-0002", Severity.High)]   // security-severity 8.0
    [InlineData("DS-0001", Severity.Medium)] // 5.5
    [InlineData("DS-0026", Severity.Low)]    // 2.0
    public void Severity_comes_from_security_severity_score(string rule, Severity expected) =>
        Assert.Equal(expected, Parse().Single(f => f.RuleId == rule).Severity);

    [Fact]
    public void Description_is_just_the_specific_message_and_title_names_the_file()
    {
        var latest = Parse().Single(f => f.RuleId == "DS-0001");

        Assert.Equal("Specify a tag in the 'FROM' statement for image 'ubuntu'", latest.Description);
        Assert.Equal("':latest' tag used in Dockerfile", latest.Title);
        Assert.StartsWith("https://avd.aquasec.com/", latest.References[0]);
    }

    [Theory]
    [InlineData("pod.yaml", "apiVersion: v1\nkind: Pod\nmetadata:\n  name: web\n", true)]
    [InlineData("stack.yaml", "AWSTemplateFormatVersion: '2010-09-09'\nResources: {}\n", true)]
    [InlineData("azuredeploy.json", "{\"$schema\": \"https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#\"}", true)]
    [InlineData("settings.yaml", "logging:\n  level: info\n", false)]
    [InlineData("package.json", "{\"name\": \"x\"}", false)]
    public void Detector_recognizes_iac_by_content(string name, string content, bool expected)
    {
        var root = Directory.CreateTempSubdirectory("nightjar-iac-").FullName;
        try
        {
            File.WriteAllText(Path.Combine(root, name), content);
            Assert.Equal(expected, IacDetector.HasIacFiles(root));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }
}
