using Nightjar.Core.Ai;
using Nightjar.Core.Findings;
using Nightjar.Core.Reports;

namespace Nightjar.Tests;

public sealed class AiReviewTests : IDisposable
{
    private readonly string _root = Directory.CreateTempSubdirectory("nightjar-ai-test-").FullName;

    public void Dispose() => Directory.Delete(_root, recursive: true);

    private sealed class FakeLlm(Func<string, string> answer) : ILlmClient
    {
        public List<string> Prompts { get; } = [];
        public string Name => "fake:model";
        public bool IsRemote => false;

        public Task<string> CompleteJsonAsync(string system, string user, string jsonSchema, CancellationToken cancellationToken)
        {
            lock (Prompts) { Prompts.Add(user); }
            return Task.FromResult(answer(user));
        }
    }

    private static Finding Vuln(string id, Severity severity, string package) => new()
    {
        Id = id,
        Category = FindingCategory.Vulnerability,
        Severity = severity,
        RuleId = "GHSA-" + id,
        Title = $"Prototype pollution in {package}",
        Package = new PackageRef(package, "4.17.0", "npm"),
    };

    private ScanReport Report(params Finding[] findings) => new()
    {
        Project = _root,
        StartedAt = DateTimeOffset.UtcNow,
        Seconds = 1,
        ManifestSequence = 0,
        Engines = [],
        Findings = findings,
    };

    private const string LikelyJson = """
        {"verdict":"likely","confidence":0.8,"reasoning":"req.body flows into merge","attack_path":["POST /settings","body merged into config"],"verification_steps":"Send a JSON body with a __proto__ key to a test instance.","remediation":"Upgrade lodash"}
        """;

    [Fact]
    public async Task Review_AttachesAssessmentAndShowsPackageUsageAsEvidence()
    {
        File.WriteAllText(Path.Combine(_root, "server.js"), "const _ = require('lodash');\napp.post('/settings', (req) => _.merge(config, req.body));\n");
        File.WriteAllText(Path.Combine(_root, "unrelated.js"), "console.log('hi');\n");
        var llm = new FakeLlm(_ => LikelyJson);

        var (report, summary) = await new ExploitabilityReviewer(llm).ReviewAsync(Report(Vuln("a", Severity.High, "lodash")), null, CancellationToken.None);

        var assessment = Assert.Single(report.Findings).Assessment;
        Assert.NotNull(assessment);
        Assert.Equal(Exploitability.Likely, assessment.Verdict);
        Assert.Equal(["server.js"], assessment.EvidenceFiles);
        Assert.Equal("fake:model", assessment.Model);
        Assert.Equal(2, assessment.AttackPath.Count);
        Assert.Equal(1, summary.Reviewed);
        Assert.Contains("<file path=\"server.js\">", llm.Prompts[0]);
        Assert.DoesNotContain("unrelated.js", llm.Prompts[0]);
    }

    [Fact]
    public async Task Review_SkipsLicensesAndLowSeverityAndRespectsMax()
    {
        var llm = new FakeLlm(_ => LikelyJson);
        var license = Vuln("lic", Severity.High, "x") with { Category = FindingCategory.License };
        var options = new ReviewOptions { MinSeverity = Severity.Medium, MaxFindings = 1 };

        var (report, summary) = await new ExploitabilityReviewer(llm, options).ReviewAsync(
            Report(Vuln("c", Severity.Critical, "a"), Vuln("h", Severity.High, "b"), Vuln("l", Severity.Low, "c"), license), null, CancellationToken.None);

        Assert.Single(llm.Prompts);
        Assert.NotNull(report.Findings[0].Assessment);
        Assert.All(report.Findings.Skip(1), f => Assert.Null(f.Assessment));
        Assert.Equal(1, summary.Skipped);
    }

    [Fact]
    public async Task Review_NeverSendsSecretFindingsOrTheirSourceToTheModel()
    {
        File.WriteAllText(Path.Combine(_root, "config.js"), "const key = 'AKIAREALSECRETVALUE1234';\n");
        var secret = new Finding
        {
            Id = "s",
            Category = FindingCategory.Secret,
            Severity = Severity.Critical,
            RuleId = "aws-access-token",
            Title = "AWS access key",
            Description = "AKIA...",
            Location = new SourceLocation("config.js", 1),
        };
        var llm = new FakeLlm(_ => LikelyJson);

        var (report, summary) = await new ExploitabilityReviewer(llm).ReviewAsync(Report(secret), null, CancellationToken.None);

        Assert.Empty(llm.Prompts);
        Assert.Null(report.Findings[0].Assessment);
        Assert.Equal(0, summary.Reviewed);
        Assert.Empty(new EvidenceCollector(_root).Collect(secret));
    }

    [Fact]
    public async Task Review_ModelFailureLeavesFindingUnchangedAndIsReported()
    {
        var llm = new FakeLlm(_ => "I can't help with that.");
        var finding = Vuln("a", Severity.Critical, "lodash");

        var (report, summary) = await new ExploitabilityReviewer(llm).ReviewAsync(Report(finding), null, CancellationToken.None);

        Assert.Equal(finding, report.Findings[0]);
        Assert.Equal(1, summary.Failed);
        Assert.Single(summary.Errors);
    }

    [Fact]
    public void Parse_ClampsConfidenceAndMapsUnknownVerdicts()
    {
        var parsed = ExploitabilityReviewer.Parse("""```json {"verdict":"maybe","confidence":7,"reasoning":"r","attack_path":[],"verification_steps":"","remediation":""} ```""", "m", []);

        Assert.Equal(Exploitability.Unknown, parsed.Verdict);
        Assert.Equal(1, parsed.Confidence);
        Assert.Null(parsed.VerificationSteps);
    }

    [Fact]
    public void Evidence_NeverReadsOutsideTheScannedTree()
    {
        var outside = Path.Combine(Path.GetDirectoryName(_root)!, "nightjar-secret-" + Guid.NewGuid() + ".txt");
        File.WriteAllText(outside, "TOP SECRET");
        try
        {
            var finding = Vuln("a", Severity.High, "zzz-not-used") with { Location = new SourceLocation("../" + Path.GetFileName(outside), 1) };
            var evidence = new EvidenceCollector(_root).Collect(finding);
            Assert.Empty(evidence);
        }
        finally
        {
            File.Delete(outside);
        }
    }

    [Fact]
    public void Prompt_WrapsRepositoryContentAsUntrustedData()
    {
        var prompt = ExploitabilityReviewer.BuildPrompt(Vuln("a", Severity.High, "lodash"), [new EvidenceExcerpt("a.js", 1, "1: x\n")]);
        Assert.Contains("<finding>", prompt);
        Assert.Contains("<file path=\"a.js\">", prompt);
        Assert.Contains("untrusted", ExploitabilityReviewer.SystemPrompt);
    }
}
