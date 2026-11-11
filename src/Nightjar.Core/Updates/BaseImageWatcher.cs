using System.Globalization;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace Nightjar.Core.Updates;

/// <summary>A parsed <c>FROM</c> line: <c>FROM [--platform=…] image[:tag][@digest] [AS stage]</c>.</summary>
public sealed record BaseImageRef(string Repository, string Tag, string? Digest)
{
    /// <summary>Canonical form Nightjar writes: pulled through the mirror, pinned by digest.</summary>
    public string ToFromValue() => $"{BaseImageWatcher.Mirror}/{Repository}:{Tag}" + (Digest is null ? "" : $"@{Digest}");
}

/// <summary>
/// Keeps the base images of self-built engine images current and reproducible. For every
/// <c>FROM</c> line it:
/// <list type="bullet">
/// <item>pulls through <see cref="Mirror"/> (Google's Docker Hub cache), so builds don't hit
/// Docker Hub's anonymous pull limit;</item>
/// <item>moves versioned tags (<c>1.26.11-alpine</c>, <c>3.24.2</c>) to the newest patch release of
/// the same minor version and variant, so security fixes land without a surprise major upgrade;</item>
/// <item>pins every tag to its current digest, so a rebuilt or moved tag (<c>bookworm-slim</c>)
/// can only change through a reviewed watcher PR.</item>
/// </list>
/// Tag lists come from Docker Hub's catalog API, digests from the mirror: neither counts toward
/// pull limits. No credentials are sent.
/// </summary>
public sealed partial class BaseImageWatcher(HttpClient registry, TimeSpan minimumAge)
{
    public const string Mirror = "mirror.gcr.io";

    private static readonly string[] ManifestTypes =
    [
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
        "application/vnd.docker.distribution.manifest.v2+json",
        "application/vnd.oci.image.manifest.v1+json",
    ];

    /// <summary>Checks one Dockerfile; with <paramref name="write"/> rewrites its FROM lines in place.</summary>
    public async Task<IReadOnlyList<PinChange>> CheckAsync(string engine, string dockerfile, bool write, CancellationToken cancellationToken)
    {
        var lines = await File.ReadAllLinesAsync(dockerfile, cancellationToken);
        var stages = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var changes = new List<PinChange>();
        var resolved = new Dictionary<string, BaseImageRef>(StringComparer.Ordinal); // same image on two lines → one lookup

        for (var i = 0; i < lines.Length; i++)
        {
            if (FromLine().Match(lines[i]) is not { Success: true } match)
            {
                continue;
            }

            var image = match.Groups["image"].Value;
            if (match.Groups["stage"].Success)
            {
                stages.Add(match.Groups["stage"].Value);
            }

            if (stages.Contains(image) && !match.Groups["stage"].Value.Equals(image, StringComparison.OrdinalIgnoreCase)
                || image.Contains('$') || image.Equals("scratch", StringComparison.OrdinalIgnoreCase)
                || Parse(image) is not { } current)
            {
                continue; // FROM <earlier stage>, ARG-based or scratch: nothing to pin.
            }

            if (!resolved.TryGetValue(image, out var next))
            {
                var tag = await NewerPatchTagAsync(current, cancellationToken) ?? current.Tag;
                var digest = await DigestAsync(current.Repository, tag, cancellationToken);
                next = resolved[image] = current with { Tag = tag, Digest = digest ?? (tag == current.Tag ? current.Digest : null) };
            }

            var updated = next.ToFromValue();
            if (updated == image)
            {
                continue;
            }

            changes.Add(new PinChange(engine, $"base image {next.Repository}", Describe(image), Describe(updated), DateTimeOffset.UtcNow));
            lines[i] = lines[i][..match.Groups["image"].Index] + updated + lines[i][(match.Groups["image"].Index + image.Length)..];
        }

        if (write && changes.Count > 0)
        {
            await File.WriteAllLinesAsync(dockerfile, lines, cancellationToken);
        }

        return changes.DistinctBy(c => (c.Repo, c.From, c.To)).ToList();
    }

    /// <summary>Parses an image reference into Docker Hub repository form (<c>library/</c> for official images).</summary>
    public static BaseImageRef? Parse(string image)
    {
        var rest = image;
        string? digest = null;
        var at = rest.IndexOf('@');
        if (at >= 0)
        {
            digest = rest[(at + 1)..];
            rest = rest[..at];
        }

        // Only Docker Hub images (directly or via the mirror) can be resolved here.
        foreach (var prefix in new[] { Mirror + "/", "docker.io/", "index.docker.io/", "registry-1.docker.io/" })
        {
            if (rest.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            {
                rest = rest[prefix.Length..];
                break;
            }
        }

        // A registry host is only present before a '/', and looks like a hostname (python:3.12-slim is not one).
        var firstSegment = rest.Split('/')[0];
        if (rest.Contains('/') && (firstSegment.Contains('.') || firstSegment.Contains(':') || firstSegment == "localhost"))
        {
            return null; // Another registry (ghcr.io, quay.io…): left alone.
        }

        var colon = rest.LastIndexOf(':');
        var (repository, tag) = colon > 0 && !rest[colon..].Contains('/') ? (rest[..colon], rest[(colon + 1)..]) : (rest, "latest");
        if (!repository.Contains('/'))
        {
            repository = "library/" + repository;
        }

        return new BaseImageRef(repository, tag, digest);
    }

    /// <summary>Newest <c>MAJOR.MINOR.PATCH[-variant]</c> tag with the same major, minor and variant, older than the minimum age.</summary>
    internal async Task<string?> NewerPatchTagAsync(BaseImageRef image, CancellationToken cancellationToken)
    {
        if (VersionTag().Match(image.Tag) is not { Success: true } current)
        {
            return null; // Moving tags (bookworm-slim, 3.12-slim) only get their digest refreshed.
        }

        var major = current.Groups[1].Value;
        var minor = current.Groups[2].Value;
        var patch = int.Parse(current.Groups[3].Value, CultureInfo.InvariantCulture);
        var variant = current.Groups[4].Value;
        var cutoff = DateTimeOffset.UtcNow - minimumAge;

        var url = $"https://hub.docker.com/v2/repositories/{image.Repository}/tags?name={major}.{minor}.&page_size=100";
        var page = await registry.GetFromJsonAsync<JsonObject>(url, cancellationToken);
        string? best = null;
        var bestPatch = patch;
        foreach (var tag in page?["results"]?.AsArray() ?? [])
        {
            var name = tag?["name"]?.GetValue<string>();
            if (name is null || VersionTag().Match(name) is not { Success: true } candidate
                || candidate.Groups[1].Value != major || candidate.Groups[2].Value != minor || candidate.Groups[4].Value != variant)
            {
                continue;
            }

            var pushed = tag?["tag_last_pushed"]?.GetValue<string>() is { } p ? DateTimeOffset.Parse(p, CultureInfo.InvariantCulture) : DateTimeOffset.MaxValue;
            var candidatePatch = int.Parse(candidate.Groups[3].Value, CultureInfo.InvariantCulture);
            if (candidatePatch > bestPatch && pushed <= cutoff)
            {
                best = name;
                bestPatch = candidatePatch;
            }
        }

        return best;
    }

    /// <summary>Digest of a tag (multi-arch index when there is one), via a HEAD request to the mirror.</summary>
    internal async Task<string?> DigestAsync(string repository, string tag, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Head, $"https://{Mirror}/v2/{repository}/manifests/{tag}");
        foreach (var type in ManifestTypes)
        {
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue(type));
        }

        using var response = await registry.SendAsync(request, cancellationToken);
        return response.IsSuccessStatusCode && response.Headers.TryGetValues("Docker-Content-Digest", out var values)
            ? values.FirstOrDefault()
            : null;
    }

    private static string Describe(string image) =>
        image.Contains('@') ? image[..(image.IndexOf('@') + 20)] + "…" : image;

    [GeneratedRegex(@"^\s*FROM\s+(?:--platform=\S+\s+)?(?<image>\S+)(?:\s+AS\s+(?<stage>\S+))?", RegexOptions.IgnoreCase)]
    private static partial Regex FromLine();

    [GeneratedRegex(@"^(\d+)\.(\d+)\.(\d+)(-[A-Za-z0-9.-]+)?$")]
    private static partial Regex VersionTag();
}
