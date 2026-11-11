using System.Collections.Concurrent;
using System.Diagnostics;
using Nightjar.Core.Updates;

namespace Nightjar.Engines.Execution;

/// <summary>
/// Makes sure an engine image is available before it runs, and returns the reference to run:
/// <list type="bullet">
/// <item>self-built images (opengrep, cppcheck, lizard, nuclei…) are built on first use from the
/// Dockerfile compiled into Nightjar (signed manifests point at published images instead);</item>
/// <item>Docker Hub images that hit the anonymous pull limit (HTTP 429) are pulled through
/// <see cref="BaseImageWatcher.Mirror"/> instead. With a digest pin the content is byte-identical,
/// so the mirror changes nothing about what runs.</item>
/// </list>
/// </summary>
public static class EngineImages
{
    public const string LocalPrefix = "nightjar-engines/";
    private const string ResourcePrefix = "engine-images/";
    private static readonly ConcurrentDictionary<string, Task<string>> Resolved = new(StringComparer.Ordinal);

    public static Task<string> ResolveAsync(EngineSpec spec, CancellationToken cancellationToken) =>
        Resolved.GetOrAdd(spec.ImageReference, _ => spec.Image.StartsWith(LocalPrefix, StringComparison.Ordinal) && spec.Digest is null
            ? BuildIfMissingAsync(spec, cancellationToken).ContinueWith(_ => spec.ImageReference, cancellationToken, TaskContinuationOptions.OnlyOnRanToCompletion, TaskScheduler.Default)
            : PullAsync(spec.ImageReference, cancellationToken));

    /// <summary>
    /// The mirror's name for a Docker Hub image, or null for other registries.
    /// <c>anchore/syft:v1</c> → <c>mirror.gcr.io/anchore/syft:v1</c>; <c>alpine@sha256:…</c> → <c>mirror.gcr.io/library/alpine@sha256:…</c>.
    /// </summary>
    public static string? MirrorReference(string reference)
    {
        var at = reference.IndexOf('@');
        var name = at >= 0 ? reference[..at] : reference;
        var pin = at >= 0 ? reference[at..] : "";
        var parsed = BaseImageWatcher.Parse(name);
        if (parsed is null || name.StartsWith(BaseImageWatcher.Mirror + "/", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        var hasTag = name.LastIndexOf(':') > name.LastIndexOf('/');
        return $"{BaseImageWatcher.Mirror}/{parsed.Repository}" + (hasTag || pin.Length == 0 ? $":{parsed.Tag}" : "") + pin;
    }

    private static async Task<string> PullAsync(string reference, CancellationToken cancellationToken)
    {
        if ((await RunDockerWithOutputAsync(["image", "inspect", reference], cancellationToken)).Code == 0)
        {
            return reference;
        }

        var (code, output) = await RunDockerWithOutputAsync(["pull", "-q", reference], cancellationToken);
        if (code == 0)
        {
            return reference;
        }

        var rateLimited = output.Contains("toomanyrequests", StringComparison.OrdinalIgnoreCase)
            || output.Contains("rate limit", StringComparison.OrdinalIgnoreCase)
            || output.Contains("429", StringComparison.Ordinal);
        if (rateLimited && MirrorReference(reference) is { } mirror
            && (await RunDockerWithOutputAsync(["pull", "-q", mirror], cancellationToken)).Code == 0)
        {
            Console.Error.WriteLine($"» Docker Hub pull limit reached; using {mirror}");
            return mirror;
        }

        return reference; // Let docker run report the real error.
    }

    public static IReadOnlyList<string> EmbeddedEngines() =>
        typeof(EngineImages).Assembly.GetManifestResourceNames()
            .Where(n => n.StartsWith(ResourcePrefix, StringComparison.Ordinal))
            .Select(n => n[ResourcePrefix.Length..].Split('/')[0])
            .Distinct()
            .ToList();

    private static async Task BuildIfMissingAsync(EngineSpec spec, CancellationToken cancellationToken)
    {
        if (await RunDockerAsync(["image", "inspect", spec.ImageReference], cancellationToken) == 0)
        {
            return;
        }

        var name = spec.Image[LocalPrefix.Length..];
        var assembly = typeof(EngineImages).Assembly;
        var files = assembly.GetManifestResourceNames().Where(n => n.StartsWith($"{ResourcePrefix}{name}/", StringComparison.Ordinal)).ToList();
        if (files.Count == 0)
        {
            return; // Nothing embedded; docker run will report the missing image.
        }

        var context = Directory.CreateTempSubdirectory($"nightjar-build-{name}-").FullName;
        try
        {
            foreach (var resource in files)
            {
                await using var stream = assembly.GetManifestResourceStream(resource)!;
                await using var file = File.Create(Path.Combine(context, resource[(ResourcePrefix.Length + name.Length + 1)..]));
                await stream.CopyToAsync(file, cancellationToken);
            }

            Console.Error.WriteLine($"» building engine image {spec.ImageReference} (first use only, can take a few minutes)...");
            if (await RunDockerAsync(["build", "-q", "-t", spec.ImageReference, context], cancellationToken) != 0)
            {
                throw new InvalidOperationException($"building {spec.ImageReference} failed; build it by hand to see why: docker build -t {spec.ImageReference} engines/{name}");
            }
        }
        finally
        {
            try { Directory.Delete(context, recursive: true); } catch (IOException) { }
        }
    }

    private static async Task<(int Code, string Output)> RunDockerWithOutputAsync(string[] args, CancellationToken cancellationToken)
    {
        var start = new ProcessStartInfo("docker") { RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (var arg in args)
        {
            start.ArgumentList.Add(arg);
        }

        try
        {
            using var process = Process.Start(start)!;
            var stdout = process.StandardOutput.ReadToEndAsync(cancellationToken);
            var stderr = process.StandardError.ReadToEndAsync(cancellationToken);
            await process.WaitForExitAsync(cancellationToken);
            return (process.ExitCode, await stdout + await stderr);
        }
        catch (System.ComponentModel.Win32Exception)
        {
            return (-1, "docker is not installed");
        }
    }

    private static async Task<int> RunDockerAsync(string[] args, CancellationToken cancellationToken)
    {
        var start = new ProcessStartInfo("docker") { RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (var arg in args)
        {
            start.ArgumentList.Add(arg);
        }

        try
        {
            using var process = Process.Start(start)!;
            _ = process.StandardOutput.ReadToEndAsync(cancellationToken);
            _ = process.StandardError.ReadToEndAsync(cancellationToken);
            await process.WaitForExitAsync(cancellationToken);
            return process.ExitCode;
        }
        catch (System.ComponentModel.Win32Exception)
        {
            return -1; // docker is not installed.
        }
    }
}
