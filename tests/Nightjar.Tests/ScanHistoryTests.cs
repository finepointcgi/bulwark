using Nightjar.Core.Findings;
using Nightjar.Core.Reports;

namespace Nightjar.Tests;

public sealed class ScanHistoryTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("nightjar-hist-").FullName;
    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private static Finding F(string id, Severity s, TriageState t = TriageState.New, FindingCategory c = FindingCategory.Vulnerability) => new()
    { Id = id, Category = c, Severity = s, RuleId = "R", Title = "t", Triage = t };

    private static ScanReport Report(DateTimeOffset at, params Finding[] findings) => new()
    { Project = "/p", StartedAt = at, Seconds = 1, ManifestSequence = 1, Engines = [], Findings = findings };

    [Fact]
    public void Records_counts_and_changes_between_scans_ignoring_triaged_and_quality()
    {
        var history = new ScanHistory(_dir);
        var first = Report(DateTimeOffset.UnixEpoch, F("a", Severity.Critical), F("b", Severity.High), F("q", Severity.Low, c: FindingCategory.Quality));
        history.Record(first, null);
        var second = Report(DateTimeOffset.UnixEpoch.AddDays(1), F("b", Severity.High), F("c", Severity.Medium), F("d", Severity.High, TriageState.FalsePositive));
        history.Record(second, first);

        File.AppendAllText(Directory.GetFiles(Path.Combine(_dir, "reports", "history")).Single(), "{torn");
        var points = history.Load("/p");

        Assert.Equal(2, points.Count);
        Assert.Equal((2, 1, 1, 0, 0), (points[0].Total, points[0].Critical, points[0].High, points[0].New, points[0].Resolved));
        Assert.Equal((2, 0, 1, 1, 1), (points[1].Total, points[1].Critical, points[1].High, points[1].New, points[1].Resolved));
    }
}
