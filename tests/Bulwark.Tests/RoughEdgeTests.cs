using Bulwark.Core.Triage;
using Bulwark.Engines.Execution;
using Bulwark.Engines.Syft;

namespace Bulwark.Tests;

public class RoughEdgeTests
{
    [Theory]
    [InlineData("src/Bulwark.Engines/Canary/Corpus/", "src/Bulwark.Engines/Canary/Corpus/src/app.py", true)]
    [InlineData("src/Bulwark.Engines/Canary/Corpus/", "src/Bulwark.Engines/Canary/CanaryCheck.cs", false)]
    [InlineData("tests/**/Fixtures/", "tests/Bulwark.Tests/Fixtures/zap.json", true)]
    [InlineData("tests/**/*Tests.cs", "tests/Bulwark.Tests/UpdaterTests.cs", true)]
    [InlineData("vendor", "lib/vendor/x.go", true)]          // no slash: matches the name anywhere
    [InlineData("vendor", "lib/vendors/x.go", false)]
    [InlineData("*.min.js", "web/app.min.js", true)]
    [InlineData("docs/*.md", "docs/a/b.md", false)]           // * stays within one folder
    [InlineData("**/generated/**", "src/generated/api.cs", true)]
    public void Ignore_patterns_follow_gitignore_style(string pattern, string path, bool ignored) =>
        Assert.Equal(ignored, IgnoreRules.Parse(["# comment", pattern]).IsIgnored(path));

    [Fact]
    public void Own_package_names_come_from_the_project_manifests()
    {
        var root = Directory.CreateTempSubdirectory("bulwark-own-").FullName;
        try
        {
            File.WriteAllText(Path.Combine(root, "package.json"), """{"name":"@acme/shop","version":"1.0.0"}""");
            File.WriteAllText(Path.Combine(root, "go.mod"), "module github.com/acme/api\n\ngo 1.23\n");
            File.WriteAllText(Path.Combine(root, "pyproject.toml"), "[project]\nname = \"acme-tools\"\nversion = \"1\"\n");
            File.WriteAllText(Path.Combine(root, "Shop.Api.csproj"), "<Project />");

            var names = OwnPackages.Find(root, ["package.json", "go.mod", "pyproject.toml", "Shop.Api.csproj"]);

            Assert.Equal(["@acme/shop", "Shop.Api", "acme-tools", "github.com/acme/api"], names.Order(StringComparer.Ordinal));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void Syft_paths_keep_a_project_folder_named_src()
    {
        const string sbom = """
            {"components":[{"type":"library","name":"left-pad","version":"1.0.0","purl":"pkg:npm/left-pad@1.0.0",
              "properties":[{"name":"syft:location:0:path","value":"/src/web/package-lock.json"}]}]}
            """;

        var component = Assert.Single(CycloneDxParser.Parse(sbom, "/Users/me/app").Components);

        Assert.Equal(["src/web/package-lock.json"], component.FoundIn);
    }

    [Fact]
    public void Unknown_licenses_are_only_flagged_where_metadata_normally_exists()
    {
        var sbom = new Bulwark.Core.Sbom.SoftwareBillOfMaterials(
        [
            new(new Bulwark.Core.Findings.PackageRef("left-pad", "1.0.0", "npm"), [], []),
            new(new Bulwark.Core.Findings.PackageRef("Newtonsoft.Json", "13.0.3", "NuGet"), [], []),
            new(new Bulwark.Core.Findings.PackageRef("actions/checkout", "v4", "GitHub Actions"), [], []),
        ], "{}");

        var findings = new Bulwark.Core.Policy.LicensePolicy().Evaluate(sbom).ToList();

        Assert.Equal("left-pad", Assert.Single(findings).Package!.Name);
    }

    [Fact]
    public void Host_user_is_uid_and_gid_on_unix()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        Assert.Matches(@"^\d+:\d+$", ToolRunner.HostUser());
    }

    [Fact]
    public void Self_built_engine_dockerfiles_are_embedded()
    {
        Assert.Contains("opengrep", EngineImages.EmbeddedEngines());
        Assert.Contains("cppcheck", EngineImages.EmbeddedEngines());
        Assert.Contains("lizard", EngineImages.EmbeddedEngines());
    }
}
