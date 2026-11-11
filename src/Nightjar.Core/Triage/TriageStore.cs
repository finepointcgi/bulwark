using System.Text.Json;
using System.Text.Json.Serialization;
using Nightjar.Core.Findings;
using Nightjar.Core.Reports;

namespace Nightjar.Core.Triage;

/// <summary>One triage decision, keyed by the finding's stable fingerprint.</summary>
public sealed record TriageDecision
{
    public required string FindingId { get; init; }
    public required TriageState State { get; init; }
    public string? Reason { get; init; }
    public string? By { get; init; }
    public required DateTimeOffset At { get; init; }

    /// <summary>Accepted risks can expire; after that the finding counts again and needs a new decision.</summary>
    public DateTimeOffset? Expires { get; init; }

    /// <summary>Title at decision time, so the file stays readable when reviewed in a PR.</summary>
    public string? Title { get; init; }

    public bool IsActive(DateTimeOffset now) => Expires is not { } e || e > now;
}

/// <summary>
/// Triage decisions that survive rescans. Two layers:
/// <list type="bullet">
/// <item>shared: <c>.nightjar/triage.json</c> in the repository, committed and reviewed like code
/// (so CI sees the same decisions as developers);</item>
/// <item>local: NIGHTJAR_HOME/triage/&lt;project&gt;.json, for personal or not-yet-shared decisions.</item>
/// </list>
/// Shared decisions win when both exist for the same finding.
/// </summary>
public sealed class TriageStore(string homeDirectory)
{
    public const string SharedFileName = ".nightjar/triage.json";

    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.KebabCaseLower) },
    };

    public string LocalPath(string project) => Path.Combine(homeDirectory, "triage", $"{ReportArchive.KeyFor(Path.GetFullPath(project))}.json");

    public static string SharedPath(string project) => Path.Combine(project, SharedFileName);

    public IReadOnlyDictionary<string, TriageDecision> Load(string project)
    {
        var decisions = new Dictionary<string, TriageDecision>(StringComparer.Ordinal);
        foreach (var path in new[] { LocalPath(project), SharedPath(project) })
        {
            foreach (var decision in Read(path))
            {
                decisions[decision.FindingId] = decision;
            }
        }

        return decisions;
    }

    /// <summary>Sets each finding's triage state from active decisions. Expired decisions are ignored.</summary>
    public IReadOnlyList<Finding> Apply(string project, IReadOnlyList<Finding> findings, DateTimeOffset now)
    {
        var decisions = Load(project);
        return findings
            .Select(f => decisions.TryGetValue(f.Id, out var d) && d.IsActive(now) ? f with { Triage = d.State } : f)
            .ToList();
    }

    /// <summary>Records a decision. <see cref="TriageState.New"/> removes it.</summary>
    public string Save(string project, TriageDecision decision, bool shared)
    {
        var path = shared ? SharedPath(project) : LocalPath(project);
        var decisions = Read(path).Where(d => d.FindingId != decision.FindingId).ToList();
        if (decision.State != TriageState.New)
        {
            decisions.Add(decision);
        }

        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var temp = path + ".tmp";
        File.WriteAllText(temp, JsonSerializer.Serialize(decisions.OrderBy(d => d.FindingId, StringComparer.Ordinal), Json) + "\n");
        File.Move(temp, path, overwrite: true);
        return path;
    }

    private static IEnumerable<TriageDecision> Read(string path)
    {
        if (!File.Exists(path))
        {
            return [];
        }

        try
        {
            return JsonSerializer.Deserialize<List<TriageDecision>>(File.ReadAllText(path), Json) ?? [];
        }
        catch (JsonException e)
        {
            throw new InvalidDataException($"Triage file {path} is not valid: {e.Message}", e);
        }
    }

    public static TriageState ParseState(string value) => value.ToLowerInvariant().Replace("_", "-") switch
    {
        "false-positive" or "fp" => TriageState.FalsePositive,
        "accepted-risk" or "accept" or "wont-fix" => TriageState.AcceptedRisk,
        "confirmed" or "confirm" => TriageState.Confirmed,
        "fixed" => TriageState.Fixed,
        "new" or "reset" or "clear" => TriageState.New,
        _ => throw new ArgumentException($"unknown triage state '{value}' (false-positive, accepted-risk, confirmed, fixed, reset)"),
    };
}
