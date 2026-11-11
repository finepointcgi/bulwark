using System.Collections.Concurrent;
using System.Diagnostics;
using Bulwark.Core.Updates;

namespace Bulwark.Engines.Execution;

/// <summary>
/// Builds a self-built engine image (opengrep, cppcheck, lizard, nuclei...) the first time it is
/// needed and not present, from the Dockerfile compiled into Bulwark. Signed manifests point at
/// published images instead, so this only matters before the first update or offline.
/// </summary>
public static class EngineImages
{
    public const string LocalPrefix = "bulwark-engines/";
    private const string ResourcePrefix = "engine-images/";
    private static readonly ConcurrentDictionary<string, Task> Ensured = new(StringComparer.Ordinal);

    public static Task EnsureAsync(EngineSpec spec, CancellationToken cancellationToken)
    {
        if (!spec.Image.StartsWith(LocalPrefix, StringComparison.Ordinal) || spec.Digest is not null)
        {
            return Task.CompletedTask; // Published images are pulled by docker run itself.
        }

        return Ensured.GetOrAdd(spec.ImageReference, _ => BuildIfMissingAsync(spec, cancellationToken));
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

        var context = Directory.CreateTempSubdirectory($"bulwark-build-{name}-").FullName;
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
