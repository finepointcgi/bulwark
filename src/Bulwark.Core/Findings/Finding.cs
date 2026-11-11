namespace Bulwark.Core.Findings;

/// <summary>What kind of problem a finding describes.</summary>
public enum FindingCategory
{
    Vulnerability,
    License,
    Secret,
    Code,
    Infrastructure,

    /// <summary>Found by active testing (DAST) against a running target.</summary>
    Dynamic,

    /// <summary>Maintainability: complexity, duplication. Never security-relevant on its own.</summary>
    Quality,
}

/// <summary>Severity, ordered so that comparisons work (Critical &gt; High &gt; ...).</summary>
public enum Severity
{
    Unknown = 0,
    Info = 1,
    Low = 2,
    Medium = 3,
    High = 4,
    Critical = 5,
}

/// <summary>Where in the source tree a finding lives. All fields optional.</summary>
public sealed record SourceLocation(string? Path, int? StartLine = null, int? EndLine = null, string? Snippet = null);

/// <summary>The third-party package a finding is about (SCA and license findings).</summary>
public sealed record PackageRef(string Name, string Version, string Ecosystem, string? Purl = null);

/// <summary>
/// One normalized finding. Every engine adapter maps its native output to this shape,
/// so triage, dedupe, policy and reporting never need to know which engine produced it.
/// </summary>
public sealed record Finding
{
    /// <summary>Stable fingerprint; identical across scans and engines for the same issue.</summary>
    public required string Id { get; init; }

    public required FindingCategory Category { get; init; }
    public required Severity Severity { get; init; }

    /// <summary>Engine-specific rule or advisory id (e.g. GHSA-xxxx, CVE-xxxx, a Semgrep rule id).</summary>
    public required string RuleId { get; init; }

    public required string Title { get; init; }
    public string? Description { get; init; }

    /// <summary>All engines that reported this finding (filled in when duplicates merge).</summary>
    public IReadOnlyList<string> Engines { get; init; } = [];

    public SourceLocation? Location { get; init; }
    public PackageRef? Package { get; init; }

    /// <summary>Other identifiers for the same issue (CVE, GHSA, OSV ids).</summary>
    public IReadOnlyList<string> Aliases { get; init; } = [];

    /// <summary>Package versions that fix a vulnerability, if known.</summary>
    public IReadOnlyList<string> FixedVersions { get; init; } = [];

    public IReadOnlyList<string> References { get; init; } = [];

    public TriageState Triage { get; init; } = TriageState.New;

    /// <summary>AI pen-test review, when `--ai` was used. Advisory; never changes severity or the gate.</summary>
    public Ai.ExploitabilityAssessment? Assessment { get; init; }
}

public enum TriageState
{
    New,
    Confirmed,
    FalsePositive,
    AcceptedRisk,
    Fixed,
}
