using System.Diagnostics;
using System.Text;
using Nightjar.Core.Updates;

namespace Nightjar.Engines.Execution;

public sealed record ToolOutput(int ExitCode, string StandardOutput, string StandardError);

/// <summary>
/// Runs an engine either from a local install or, if it is not on PATH, from its pinned
/// container image. Adapters write arguments with <see cref="SourceToken"/> and
/// <see cref="WorkToken"/> placeholders and never care which mode is used.
/// </summary>
public sealed class ToolRunner(EngineManifest manifest, ToolMode mode = ToolMode.Auto, string? cacheRoot = null)
{
    public const string SourceToken = "${SRC}";
    public const string WorkToken = "${WORK}";

    /// <summary>A per-engine folder that survives between scans (vulnerability databases and the like).</summary>
    public const string CacheToken = "${CACHE}";

    private const string ContainerSource = "/src";
    private const string ContainerWork = "/work";
    private const string ContainerCache = "/cache";

    private string CacheFor(string engine)
    {
        var path = Path.Combine(cacheRoot ?? Path.Combine(Path.GetTempPath(), "nightjar-cache"), engine);
        Directory.CreateDirectory(path);
        return path;
    }

    public EngineManifest Manifest { get; } = manifest;

    public EngineSpec Spec(string engine) =>
        Manifest.Find(engine) ?? throw new InvalidOperationException($"Engine '{engine}' is not in the manifest.");

    /// <summary>How the engine will be launched, for <c>nightjar engines</c> output.</summary>
    public string Describe(string engine)
    {
        var spec = Spec(engine);
        return UseLocal(spec) is { } local ? $"local {local}" : $"container {spec.ImageReference}";
    }

    /// <summary>True when the engine will run from its pinned container rather than a local binary.</summary>
    public bool IsContainer(string engine) => UseLocal(Spec(engine)) is null;

    /// <param name="containerWorkPath">Where to mount <paramref name="workPath"/> in the container, for tools that insist on their own directory (ZAP uses /zap/wrk).</param>
    public async Task<ToolOutput> RunAsync(
        string engine, IReadOnlyList<string> arguments, string sourcePath, string workPath,
        TimeSpan timeout, CancellationToken cancellationToken,
        IReadOnlyDictionary<string, string>? environment = null,
        string? containerWorkPath = null)
    {
        var containerWork = containerWorkPath ?? ContainerWork;
        var spec = Spec(engine);
        var cache = arguments.Any(a => a.Contains(CacheToken, StringComparison.Ordinal)) ? CacheFor(engine) : null;
        // Build a missing self-built image, or fall back to the mirror if Docker Hub rate-limits the pull.
        var image = UseLocal(spec) is null ? await EngineImages.ResolveAsync(spec, cancellationToken) : spec.ImageReference;
        string? containerName = null;
        environment ??= new Dictionary<string, string>();
        var startInfo = new ProcessStartInfo
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };

        if (UseLocal(spec) is { } localPath)
        {
            ConfigureLocal(startInfo, localPath, arguments, environment, sourcePath, workPath, cache);
        }
        else
        {
            containerName = ConfigureContainer(startInfo, engine, image, arguments, environment, sourcePath, workPath, containerWork, cache);
        }

        using var process = new Process { StartInfo = startInfo };
        var stdout = new StringBuilder();
        var stderr = new StringBuilder();
        process.OutputDataReceived += (_, e) => { if (e.Data is not null) { stdout.AppendLine(e.Data); } };
        process.ErrorDataReceived += (_, e) => { if (e.Data is not null) { stderr.AppendLine(e.Data); } };

        process.Start();
        process.BeginOutputReadLine();
        process.BeginErrorReadLine();

        using var timeoutSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutSource.CancelAfter(timeout);
        try
        {
            await process.WaitForExitAsync(timeoutSource.Token);
        }
        catch (OperationCanceledException)
        {
            process.Kill(entireProcessTree: true);
            if (containerName is not null)
            {
                RemoveContainer(containerName);
            }

            if (cancellationToken.IsCancellationRequested)
            {
                throw;
            }

            throw new TimeoutException($"{engine} did not finish within {timeout.TotalSeconds:0}s.");
        }

        return new ToolOutput(process.ExitCode, stdout.ToString(), stderr.ToString());
    }

    private static void ConfigureLocal(
        ProcessStartInfo startInfo, string localPath, IReadOnlyList<string> arguments, IReadOnlyDictionary<string, string> environment,
        string sourcePath, string workPath, string? cache)
    {
        startInfo.FileName = localPath;
        foreach (var argument in arguments)
        {
            startInfo.ArgumentList.Add(argument.Replace(SourceToken, sourcePath).Replace(WorkToken, workPath).Replace(CacheToken, cache ?? ""));
        }

        foreach (var (key, value) in environment)
        {
            startInfo.Environment[key] = value;
        }
    }

    /// <summary>Builds the <c>docker run</c> command line and returns the container's name.</summary>
    private static string ConfigureContainer(
        ProcessStartInfo startInfo, string engine, string image, IReadOnlyList<string> arguments, IReadOnlyDictionary<string, string> environment,
        string sourcePath, string workPath, string containerWork, string? cache)
    {
        startInfo.FileName = "docker";

        // Named so a timeout can remove it: killing the docker client leaves the container running.
        var containerName = $"nightjar-{engine}-{Guid.NewGuid():N}"[..40];
        foreach (var argument in (string[])
        [
            "run", "--rm", "--name", containerName,
            "--network", "bridge",
            // DAST engines reach Nightjar's scope proxy on the host. Docker Desktop defines this
            // name already; on Linux it needs mapping to the bridge gateway.
            "--add-host", "host.docker.internal:host-gateway",
            "-v", $"{sourcePath}:{ContainerSource}:ro",
            "-v", $"{workPath}:{containerWork}",
        ])
        {
            startInfo.ArgumentList.Add(argument);
        }

        if (cache is not null)
        {
            startInfo.ArgumentList.Add("-v");
            startInfo.ArgumentList.Add($"{cache}:{ContainerCache}");
        }

        AddUserArguments(startInfo, engine, environment);

        // Pass names only (`-e KEY`) and let docker read values from its own environment, so
        // values such as auth tokens never appear on a command line visible in `ps`.
        foreach (var (key, value) in environment)
        {
            startInfo.ArgumentList.Add("-e");
            startInfo.ArgumentList.Add(key);
            startInfo.Environment[key] = value;
        }

        startInfo.ArgumentList.Add(image);
        foreach (var argument in arguments)
        {
            startInfo.ArgumentList.Add(argument.Replace(SourceToken, ContainerSource).Replace(WorkToken, containerWork).Replace(CacheToken, ContainerCache));
        }

        return containerName;
    }

    /// <summary>
    /// On Linux, bind mounts keep host ownership: run as the invoking user so the engine can
    /// write to the work folder and Nightjar can delete what it wrote. (Docker Desktop on
    /// macOS/Windows maps ownership itself.) ZAP's image needs its own user and home.
    /// </summary>
    private static void AddUserArguments(ProcessStartInfo startInfo, string engine, IReadOnlyDictionary<string, string> environment)
    {
        if (!OperatingSystem.IsLinux() || engine.Equals("zap", StringComparison.OrdinalIgnoreCase) || HostUser() is not { } user)
        {
            return;
        }

        startInfo.ArgumentList.Add("--user");
        startInfo.ArgumentList.Add(user);
        if (!environment.ContainsKey("HOME"))
        {
            startInfo.ArgumentList.Add("-e");
            startInfo.ArgumentList.Add("HOME=/tmp");
        }
    }

    [System.Runtime.InteropServices.DllImport("libc", EntryPoint = "getuid")]
    private static extern uint GetUid();

    [System.Runtime.InteropServices.DllImport("libc", EntryPoint = "getgid")]
    private static extern uint GetGid();

    /// <summary>"uid:gid" of this process on Unix, or null if it cannot be determined.</summary>
    internal static string? HostUser()
    {
        try
        {
            return $"{GetUid()}:{GetGid()}";
        }
        catch (Exception e) when (e is DllNotFoundException or EntryPointNotFoundException)
        {
            return null;
        }
    }

    private static void RemoveContainer(string name)
    {
        try
        {
            using var remove = Process.Start(new ProcessStartInfo("docker", ["rm", "-f", name])
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            });
            remove?.WaitForExit(TimeSpan.FromSeconds(30));
        }
        catch (System.ComponentModel.Win32Exception)
        {
            // docker isn't available; nothing was started.
        }
    }

    /// <summary>Turns a path reported from inside the container back into a project-relative path.</summary>
    public static string ToProjectPath(string reportedPath, string sourcePath)
    {
        var path = reportedPath.Replace('\\', '/');
        foreach (var prefix in new[] { ContainerSource + "/", sourcePath.Replace('\\', '/').TrimEnd('/') + "/" })
        {
            if (path.StartsWith(prefix, StringComparison.Ordinal))
            {
                return path[prefix.Length..];
            }
        }

        return path.TrimStart('/');
    }

    private string? UseLocal(EngineSpec spec) => mode switch
    {
        ToolMode.Container => null,
        _ => FindOnPath(spec.Binary),
    };

    private static string? FindOnPath(string binary)
    {
        var names = OperatingSystem.IsWindows() ? new[] { binary + ".exe", binary } : [binary];
        var directories = (Environment.GetEnvironmentVariable("PATH") ?? "").Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries);
        return directories.SelectMany(d => names.Select(n => Path.Combine(d, n))).FirstOrDefault(File.Exists);
    }
}

public enum ToolMode
{
    /// <summary>Local binary if installed, otherwise the pinned container.</summary>
    Auto,

    /// <summary>Always the pinned container: reproducible, and the only mode that guarantees the manifest version.</summary>
    Container,
}
