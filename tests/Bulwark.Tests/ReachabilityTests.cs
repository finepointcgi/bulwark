using Bulwark.Core.Dependencies;
using Bulwark.Core.Findings;

namespace Bulwark.Tests;

public sealed class ReachabilityTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("bulwark-reach-").FullName;
    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private static Finding Vuln(string name, string ecosystem) => new()
    {
        Id = name, Category = FindingCategory.Vulnerability, Severity = Severity.High, RuleId = "X", Title = "t",
        Package = new PackageRef(name, "1.0.0", ecosystem),
    };

    [Fact]
    public void Marks_packages_by_whether_first_party_code_imports_them()
    {
        File.WriteAllText(Path.Combine(_dir, "app.js"), "const _ = require('lodash/fp');\nimport x from \"@scope/pkg\";\nimport './local';");
        File.WriteAllText(Path.Combine(_dir, "main.py"), "import requests\nfrom yaml import safe_load\n");
        File.WriteAllText(Path.Combine(_dir, "main.go"), "package main\nimport (\n\t\"github.com/gin-gonic/gin\"\n\t\"fmt\"\n)\n");
        File.WriteAllText(Path.Combine(_dir, "Program.cs"), "using Newtonsoft.Json;\nusing System;\n");
        Directory.CreateDirectory(Path.Combine(_dir, "node_modules", "dead"));
        File.WriteAllText(Path.Combine(_dir, "node_modules", "dead", "i.js"), "require('left-pad')");

        var findings = new[]
        {
            Vuln("lodash", "npm"), Vuln("@scope/pkg", "npm"), Vuln("left-pad", "npm"),
            Vuln("requests", "PyPI"), Vuln("PyYAML", "PyPI"), Vuln("urllib3", "PyPI"),
            Vuln("github.com/gin-gonic/gin", "Go"), Vuln("github.com/other/mod", "Go"),
            Vuln("Newtonsoft.Json", "NuGet"), Vuln("Serilog", "NuGet"),
            Vuln("rails", "RubyGems"),
        };

        var result = ReachabilityAnalyzer.Annotate(_dir, findings).ToDictionary(f => f.Id, f => f.Reachability);

        Assert.Equal(Reachability.Imported, result["lodash"]);
        Assert.Equal(Reachability.Imported, result["@scope/pkg"]);
        Assert.Equal(Reachability.NotImported, result["left-pad"]); // node_modules is not first-party
        Assert.Equal(Reachability.Imported, result["requests"]);
        Assert.Equal(Reachability.Imported, result["PyYAML"]);
        Assert.Equal(Reachability.NotImported, result["urllib3"]);
        Assert.Equal(Reachability.Imported, result["github.com/gin-gonic/gin"]);
        Assert.Equal(Reachability.NotImported, result["github.com/other/mod"]);
        Assert.Equal(Reachability.Imported, result["Newtonsoft.Json"]);
        Assert.Equal(Reachability.NotImported, result["Serilog"]);
        Assert.Equal(Reachability.Unknown, result["rails"]);
    }
}

public sealed class RulePackTests
{
    [Fact]
    public void Bundled_rule_pack_includes_the_web_taint_rules()
    {
        var resources = typeof(Bulwark.Engines.Opengrep.OpengrepEngine).Assembly.GetManifestResourceNames();
        Assert.Contains("rules/taint-web.yaml", resources);
    }
}
