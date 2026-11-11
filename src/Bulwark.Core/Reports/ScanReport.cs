using System.Text.Json;
using System.Text.Json.Serialization;
using Bulwark.Core.Findings;

namespace Bulwark.Core.Reports;

public sealed record EngineRun(string Engine, string Version, bool Succeeded, double Seconds, string? Error);

/// <summary>Everything one scan produced. Written to .bulwark/last-scan.json and read by the dashboard.</summary>
public sealed record ScanReport
{
    public required string Project { get; init; }
    public required DateTimeOffset StartedAt { get; init; }
    public required double Seconds { get; init; }
    public required long ManifestSequence { get; init; }
    public required IReadOnlyList<EngineRun> Engines { get; init; }
    public required IReadOnlyList<Finding> Findings { get; init; }

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
