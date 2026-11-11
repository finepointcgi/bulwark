using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace Bulwark.Core.Updates;

public sealed record PinChange(string Engine, string Repo, string From, string To, DateTimeOffset Published);

/// <summary>
/// Checks each engine's upstream GitHub releases and moves pins to the newest release that is
/// at least <see cref="MinimumAge"/> old. The delay lets the community catch bad or compromised
/// releases before Bulwark ships them. Dockerfile pins (versions, asset hashes, base images)
/// are rewritten in the same pass so a bump is one reviewable PR.
/// </summary>
public sealed partial class EngineWatcher(HttpClient github, TimeSpan minimumAge)
{
    public TimeSpan MinimumAge { get; } = minimumAge;

    public async Task<(EngineCatalog Catalog, IReadOnlyList<PinChange> Changes)> CheckAsync(
        EngineCatalog catalog, string repositoryRoot, bool write, CancellationToken cancellationToken)
    {
        var changes = new List<PinChange>();
        var engines = new List<CatalogEngine>();

        foreach (var engine in catalog.Engines)
        {
            var pins = new List<UpstreamPin>();
            foreach (var pin in engine.Upstream)
            {
                var release = await NewestMatureReleaseAsync(pin.Repo, cancellationToken);
                if (release is null || release.Tag == pin.Tag || !IsNewer(release.Tag, pin.Tag))
                {
                    pins.Add(pin);
                    continue;
                }

                if (write && engine.Build is not null && pin.Dockerfile is { Count: > 0 })
                {
                    await RewriteDockerfileAsync(Path.Combine(repositoryRoot, engine.Build, "Dockerfile"), pin, release, cancellationToken);
                }

                changes.Add(new PinChange(engine.Name, pin.Repo, pin.Tag, release.Tag, release.Published));
                pins.Add(pin with { Tag = release.Tag });
            }

            engines.Add(engine with { Upstream = pins });
        }

        return (new EngineCatalog(engines), changes);
    }

    private async Task<Release?> NewestMatureReleaseAsync(string repo, CancellationToken cancellationToken)
    {
        var releases = await github.GetFromJsonAsync<List<GitHubRelease>>(
            $"https://api.github.com/repos/{repo}/releases?per_page=30", cancellationToken) ?? [];

        var cutoff = DateTimeOffset.UtcNow - MinimumAge;
        return releases
            .Where(r => !r.Draft && !r.Prerelease && r.PublishedAt is { } p && p <= cutoff && StableTag().IsMatch(r.TagName))
            .OrderByDescending(r => r.PublishedAt)
            .Select(r => new Release(r.TagName, r.PublishedAt!.Value, r.Assets ?? []))
            .FirstOrDefault();
    }

    /// <summary>Only moves forward: a re-published old release must never downgrade an engine.</summary>
    internal static bool IsNewer(string candidate, string current) =>
        Version.TryParse(Numeric(candidate), out var a) && Version.TryParse(Numeric(current), out var b) && a > b;

    private static string Numeric(string tag)
    {
        var parts = tag.TrimStart('v').Split('.').Take(4).ToList();
        while (parts.Count < 2) { parts.Add("0"); }
        return string.Join('.', parts);
    }

    private async Task RewriteDockerfileAsync(string dockerfile, UpstreamPin pin, Release release, CancellationToken cancellationToken)
    {
        var text = await File.ReadAllTextAsync(dockerfile, cancellationToken);
        foreach (var (key, template) in pin.Dockerfile!)
        {
            var value = await ResolveAsync(template, pin.Repo, release, cancellationToken);
            text = key == "FROM"
                ? Regex.Replace(text, @"(?m)^FROM\s+\S+", $"FROM {value}")
                : Regex.Replace(text, $@"(?m)^ARG\s+{Regex.Escape(key)}=\S*", $"ARG {key}={value}");
        }

        await File.WriteAllTextAsync(dockerfile, text, cancellationToken);
    }

    private async Task<string> ResolveAsync(string template, string repo, Release release, CancellationToken cancellationToken)
    {
        const string assetPrefix = "asset-sha256:";
        if (template.StartsWith(assetPrefix, StringComparison.Ordinal))
        {
            var name = template[assetPrefix.Length..];
            var asset = release.Assets.FirstOrDefault(a => a.Name == name)
                ?? throw new InvalidDataException($"{repo} {release.Tag} has no asset '{name}'.");

            // GitHub publishes asset digests; fall back to hashing the download if it does not.
            return asset.Digest is { } digest && digest.StartsWith("sha256:", StringComparison.Ordinal)
                ? digest["sha256:".Length..]
                : await Sha256Async(asset.BrowserDownloadUrl, cancellationToken);
        }

        if (template == "tarball-sha256")
        {
            return await Sha256Async($"https://github.com/{repo}/archive/refs/tags/{release.Tag}.tar.gz", cancellationToken);
        }

        return UpstreamPin.Format(template, release.Tag);
    }

    private async Task<string> Sha256Async(string url, CancellationToken cancellationToken)
    {
        await using var stream = await github.GetStreamAsync(url, cancellationToken);
        return Convert.ToHexStringLower(await SHA256.HashDataAsync(stream, cancellationToken));
    }

    [GeneratedRegex(@"^v?\d+(\.\d+){1,3}$")]
    private static partial Regex StableTag();

    private sealed record Release(string Tag, DateTimeOffset Published, IReadOnlyList<GitHubAsset> Assets);

    private sealed record GitHubRelease(
        [property: JsonPropertyName("tag_name")] string TagName,
        [property: JsonPropertyName("draft")] bool Draft,
        [property: JsonPropertyName("prerelease")] bool Prerelease,
        [property: JsonPropertyName("published_at")] DateTimeOffset? PublishedAt,
        [property: JsonPropertyName("assets")] List<GitHubAsset>? Assets);

    private sealed record GitHubAsset(
        [property: JsonPropertyName("name")] string Name,
        [property: JsonPropertyName("digest")] string? Digest,
        [property: JsonPropertyName("browser_download_url")] string BrowserDownloadUrl);
}
