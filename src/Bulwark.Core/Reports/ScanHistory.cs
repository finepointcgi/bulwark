using System.Text.Json;
using Bulwark.Core.Findings;

namespace Bulwark.Core.Reports;

/// <summary>One point on a project's trend line.</summary>
public sealed record HistoryPoint(
    DateTimeOffset At,
    int Total,
    int Critical,
    int High,
    int Medium,
    int Low,
    int New,
    int Resolved,
    Dictionary<string, double>? Metrics);

/// <summary>
/// Append-only trend history, one JSON line per scan, under BULWARK_HOME/reports/history.
/// Plain text on purpose: no native database dependency, so the single-file CLI stays portable
/// and the history can be inspected, diffed or deleted with ordinary tools.
/// </summary>
public sealed class ScanHistory(string homeDirectory)
{
    private const int MaxPoints = 1000;
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    private string PathFor(string project) => Path.Combine(homeDirectory, "reports", "history", $"{ReportArchive.KeyFor(project)}.jsonl");

    /// <summary>Open findings only: ones triaged as false positive or fixed don't count toward the trend.</summary>
    public static HistoryPoint Snapshot(ScanReport report, ScanReport? previous)
    {
        static IEnumerable<Finding> Open(ScanReport r) =>
            r.Findings.Where(f => f.Category != FindingCategory.Quality && f.Triage is TriageState.New or TriageState.Confirmed or TriageState.AcceptedRisk);

        var open = Open(report).ToList();
        var before = previous is null ? null : Open(previous).Select(f => f.Id).ToHashSet(StringComparer.Ordinal);
        var now = open.Select(f => f.Id).ToHashSet(StringComparer.Ordinal);
        return new HistoryPoint(
            report.StartedAt,
            open.Count,
            open.Count(f => f.Severity == Severity.Critical),
            open.Count(f => f.Severity == Severity.High),
            open.Count(f => f.Severity == Severity.Medium),
            open.Count(f => f.Severity <= Severity.Low),
            before is null ? 0 : now.Count(id => !before.Contains(id)),
            before is null ? 0 : before.Count(id => !now.Contains(id)),
            report.Metrics is { Count: > 0 } m ? new Dictionary<string, double>(m) : null);
    }

    public void Record(ScanReport report, ScanReport? previous)
    {
        var path = PathFor(report.Project);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.AppendAllText(path, JsonSerializer.Serialize(Snapshot(report, previous), Json) + "\n");
        Trim(path);
    }

    public IReadOnlyList<HistoryPoint> Load(string project)
    {
        var path = PathFor(project);
        if (!File.Exists(path))
        {
            return [];
        }

        var points = new List<HistoryPoint>();
        foreach (var line in File.ReadLines(path).Where(l => l.Length > 0))
        {
            try
            {
                if (JsonSerializer.Deserialize<HistoryPoint>(line, Json) is { } point) { points.Add(point); }
            }
            catch (JsonException)
            {
                // A torn last line from a crash must not hide the rest of the history.
            }
        }

        return points;
    }

    private static void Trim(string path)
    {
        var lines = File.ReadAllLines(path);
        if (lines.Length > MaxPoints)
        {
            File.WriteAllLines(path, lines[^MaxPoints..]);
        }
    }
}
