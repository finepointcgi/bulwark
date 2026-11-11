using Nightjar.Core.Findings;
using Nightjar.Engines.Gitleaks;

namespace Nightjar.Tests;

public class SecretHistoryTests
{
    private const string Current = "ghp_CURRENTcurrentCURRENTcurrent0001";
    private const string Removed = "ghp_REMOVEDremovedREMOVEDremoved0002";

    private static string DirReport() =>
        $$"""[{"RuleID":"github-pat","Description":"GitHub PAT","StartLine":3,"Secret":"{{Current}}","File":"/src/app.env"}]""";

    private static string HistoryReport() => $$"""
        [
          {"RuleID":"github-pat","Description":"GitHub PAT","StartLine":1,"Secret":"{{Current}}","File":"app.env",
           "Commit":"eff981cf152185a4404538091a6ddce9116cdef4","Date":"2026-03-02T10:00:00Z","Author":"Dev","Email":"dev@example.invalid"},
          {"RuleID":"github-pat","Description":"GitHub PAT","StartLine":1,"Secret":"{{Removed}}","File":"config.env",
           "Commit":"60d9917b64571ef65396a8a3bc6093b9e2a83054","Date":"2025-12-24T10:00:00Z","Author":"Dev","Email":"dev@example.invalid"},
          {"RuleID":"github-pat","Description":"GitHub PAT","StartLine":1,"Secret":"{{Removed}}","File":"config.env",
           "Commit":"aaaaaaa0000000000000000000000000000000000","Date":"2026-01-10T10:00:00Z","Author":"Dev","Email":"dev@example.invalid"}
        ]
        """;

    [Fact]
    public void Secret_in_tree_and_history_becomes_one_finding_with_first_commit()
    {
        var combined = Combine();

        var current = Assert.Single(combined, f => f.Location!.Path == "app.env");
        Assert.Equal(3, current.Location!.StartLine);
        Assert.Contains("In git history since commit eff981c (2026-03-02)", current.Description);
    }

    [Fact]
    public void Removed_secret_is_reported_once_from_its_earliest_commit()
    {
        var removed = Assert.Single(Combine(), f => f.Location!.Path == "config.env");

        Assert.StartsWith("Secret in git history (github-pat)", removed.Title);
        Assert.Contains("commit 60d9917 (2025-12-24)", removed.Description);
        Assert.Contains("ghp_****", removed.Description);
        Assert.Equal(FindingCategory.Secret, removed.Category);
    }

    [Fact]
    public void Combined_output_has_no_secret_values_or_author_details()
    {
        var text = string.Join("\n", Combine().Select(f => $"{f.Title} {f.Description}"));

        Assert.DoesNotContain(Current, text);
        Assert.DoesNotContain(Removed, text);
        Assert.DoesNotContain("dev@example.invalid", text);
        Assert.Equal(2, Combine().Count);
    }

    [Theory]
    [InlineData(null, true, null)]
    [InlineData("full", true, null)]
    [InlineData("off", false, null)]
    [InlineData("origin/main..HEAD", true, "origin/main..HEAD")]
    public void History_option_parses(string? value, bool enabled, string? logOptions)
    {
        var scope = HistoryScope.Parse(value);
        Assert.Equal(enabled, scope.Enabled);
        Assert.Equal(logOptions, scope.LogOptions);
    }

    private static IReadOnlyList<Finding> Combine() => GitleaksParser.Combine(
        GitleaksParser.Parse(DirReport(), "/Users/me/app", "gitleaks"),
        GitleaksParser.ParseLeaks(HistoryReport(), "/Users/me/app", "gitleaks"));
}
