using System.Text.Json;
using System.Text.Json.Serialization;
using Nightjar.Core.Findings;

namespace Nightjar.Core.Reports;

public sealed record EngineRun(string Engine, string Version, bool Succeeded, double Seconds, string? Error);

/// <summary>Everything one scan produced. Written to .nightjar/last-scan.json and read by the dashboard.</summary>
public sealed record ScanReport
{
    public required string Project { get; init; }
    public required DateTimeOffset StartedAt { get; init; }
    public required double Seconds { get; init; }
    public required long ManifestSequence { get; init; }
    public required IReadOnlyList<EngineRun> Engines { get; init; }
    public required IReadOnlyList<Finding> Findings { get; init; }

    /// <summary>Set for active tests (`nightjar pentest`): who authorized it, what was sent, what the AI planned.</summary>
    public Dast.PentestSummary? Pentest { get; init; }

    /// <summary>Project-wide numbers (see <see cref="Quality.MetricNames"/>): coverage, duplication, complexity.</summary>
    public IReadOnlyDictionary<string, double>? Metrics { get; init; }

    public static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters = { new JsonStringEnumConverter() },
    };

    public string ToJson() => JsonSerializer.Serialize(this, JsonOptions);

    public static ScanReport FromJson(string json) =>
        JsonSerializer.Deserialize<ScanReport>(json, JsonOptions) ?? throw new InvalidDataException("Empty report.");
}
