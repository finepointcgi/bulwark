using System.Text.Json;
using System.Text.Json.Nodes;

namespace Bulwark.Core.Updates;

/// <summary>
/// engines/engines.json: the one place engine versions are declared. The built-in manifest,
/// the release pipeline (<c>bulwark manifest generate</c>) and the upstream watcher
/// (<c>bulwark engines watch</c>) all read it, so they can never disagree.
/// </summary>
public sealed record EngineCatalog(IReadOnlyList<CatalogEngine> Engines)
{
    private static readonly JsonSerializerOptions Options = new(JsonSerializerDefaults.Web) { WriteIndented = true };

    public static EngineCatalog Parse(string json)
    {
        var root = JsonNode.Parse(json)?.AsObject() ?? throw new InvalidDataException("Empty engine catalog.");
        var engines = root["engines"]?.Deserialize<List<CatalogEngine>>(Options)
            ?? throw new InvalidDataException("Engine catalog has no 'engines'.");
        return new EngineCatalog(engines);
    }

    public static EngineCatalog Load(string path) => Parse(File.ReadAllText(path));

    /// <summary>The copy compiled into Bulwark, used before the first signed manifest is installed.</summary>
    public static EngineCatalog Embedded()
    {
        using var stream = typeof(EngineCatalog).Assembly.GetManifestResourceStream("engines.json")
            ?? throw new InvalidOperationException("engines.json is not embedded in Bulwark.Core.");
        using var reader = new StreamReader(stream);
        return Parse(reader.ReadToEnd());
    }

    /// <summary>
    /// Builds a manifest. <paramref name="imagePrefix"/> replaces the local <c>bulwark-engines</c>
    /// namespace of self-built images with the registry they were pushed to.
    /// </summary>
    public EngineManifest ToManifest(
        long sequence, string channel, DateTimeOffset published,
        IReadOnlyDictionary<string, string>? digests = null, string? imagePrefix = null, BulwarkRelease? bulwark = null) => new()
    {
        SchemaVersion = EngineManifest.CurrentSchemaVersion,
        Channel = channel,
        Sequence = sequence,
        Published = published,
        Bulwark = bulwark,
        Engines = Engines.Select(e => new EngineSpec
        {
            Name = e.Name,
            Version = e.Version,
            Binary = e.Binary,
            Image = e.Build is not null && imagePrefix is not null ? $"{imagePrefix.TrimEnd('/')}/{e.Name}" : e.Image,
            Digest = digests?.GetValueOrDefault(e.Name),
        }).ToList(),
    };

    /// <summary>Writes the catalog back, keeping the top-level comment.</summary>
    public void Save(string path)
    {
        var root = File.Exists(path) ? JsonNode.Parse(File.ReadAllText(path))!.AsObject() : new JsonObject();
        root["engines"] = JsonSerializer.SerializeToNode(Engines, Options);
        File.WriteAllText(path, root.ToJsonString(Options) + "\n");
    }
}

public sealed record CatalogEngine
{
    public required string Name { get; init; }
    public required string Binary { get; init; }

    /// <summary>Upstream image, or <c>bulwark-engines/NAME</c> for images Bulwark builds itself.</summary>
    public required string Image { get; init; }

    /// <summary>Folder with the Dockerfile, for engines without a usable upstream image.</summary>
    public string? Build { get; init; }

    public required IReadOnlyList<UpstreamPin> Upstream { get; init; }

    /// <summary>The image tag: the first pin that declares a <c>version</c> format decides it.</summary>
    public string Version
    {
        get
        {
            var pin = Upstream.FirstOrDefault(p => p.Version is not null)
                ?? throw new InvalidDataException($"Engine '{Name}' has no upstream pin with a version format.");
            return UpstreamPin.Format(pin.Version!, pin.Tag);
        }
    }
}

/// <summary>One upstream GitHub repository an engine depends on, pinned to a release tag.</summary>
public sealed record UpstreamPin
{
    public required string Repo { get; init; }
    public required string Tag { get; init; }

    /// <summary>How the tag becomes the engine version: <c>{tag}</c> or <c>{bare}</c> (no leading v).</summary>
    public string? Version { get; init; }

    /// <summary>Dockerfile values to rewrite when the pin moves (ARG name or FROM → template).</summary>
    public IReadOnlyDictionary<string, string>? Dockerfile { get; init; }

    public static string Format(string template, string tag) =>
        template.Replace("{tag}", tag).Replace("{bare}", tag.StartsWith('v') ? tag[1..] : tag);
}
