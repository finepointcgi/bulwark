using System.Text.Json;
using System.Text.Json.Serialization;

namespace Nightjar.Core.Updates;

/// <summary>
/// The signed list of engine versions Nightjar is allowed to run. Published by the project,
/// verified on every update, and stored locally as the lockfile for all scans.
/// </summary>
public sealed record EngineManifest
{
    public const int CurrentSchemaVersion = 1;

    public required int SchemaVersion { get; init; }
    public required string Channel { get; init; }

    /// <summary>Monotonic sequence number. The updater refuses anything lower than what it has (rollback protection).</summary>
    public required long Sequence { get; init; }

    public required DateTimeOffset Published { get; init; }
    public required IReadOnlyList<EngineSpec> Engines { get; init; }

    /// <summary>Latest Nightjar release, for <c>nightjar self-update</c>. Covered by the manifest signature.</summary>
    public NightjarRelease? Nightjar { get; init; }

    public EngineSpec? Find(string name) =>
        Engines.FirstOrDefault(e => e.Name.Equals(name, StringComparison.OrdinalIgnoreCase));

    public static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) },
    };

    public static EngineManifest Parse(ReadOnlySpan<byte> json) =>
        JsonSerializer.Deserialize<EngineManifest>(json, JsonOptions)
        ?? throw new InvalidDataException("Manifest is empty.");
}

/// <summary>A Nightjar CLI release: one self-contained binary per runtime identifier, pinned by SHA-256.</summary>
public sealed record NightjarRelease
{
    public required string Version { get; init; }
    public required IReadOnlyList<NightjarAsset> Assets { get; init; }
}

/// <param name="Rid">.NET runtime identifier, e.g. <c>linux-x64</c>, <c>osx-arm64</c>, <c>win-x64</c>.</param>
public sealed record NightjarAsset(string Rid, string Url, string Sha256);

/// <summary>One engine pinned to an exact version and container image digest.</summary>
public sealed record EngineSpec
{
    public required string Name { get; init; }
    public required string Version { get; init; }

    /// <summary>Container image without tag, e.g. <c>docker.io/anchore/syft</c>.</summary>
    public required string Image { get; init; }

    /// <summary>Image digest (<c>sha256:...</c>). Required in signed manifests so a moved tag cannot swap the engine.</summary>
    public string? Digest { get; init; }

    /// <summary>Executable name if the engine is installed locally instead of run in a container.</summary>
    public required string Binary { get; init; }

    public string ImageReference => Digest is { Length: > 0 } ? $"{Image}@{Digest}" : $"{Image}:{Version}";
}
