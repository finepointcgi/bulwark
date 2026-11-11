using System.Diagnostics;
using System.Text;
using Bulwark.Core.Updates;

namespace Bulwark.Engines.Execution;

public sealed record ToolOutput(int ExitCode, string StandardOutput, string StandardError);

/// <summary>
/// Runs an engine either from a local install or, if it is not on PATH, from its pinned
/// container image. Adapters write arguments with <see cref="SourceToken"/> and
/// <see cref="WorkToken"/> placeholders and never care which mode is used.
/// </summary>
public sealed class ToolRunner(EngineManifest manifest, ToolMode mode = ToolMode.Auto)
{
    public const string SourceToken = "${SRC}";
    public const string WorkToken = "${WORK}";

    private const string ContainerSource = "/src";
    private const string ContainerWork = "/work";

    public EngineManifest Manifest { get; } = manifest;

    public EngineSpec Spec(string engine) =>
        Manifest.Find(engine) ?? throw new InvalidOperationException($"Engine '{engine}' is not in the manifest.");

    /// <summary>How the engine will be launched, for <c>bulwark engines</c> output.</summary>
    public string Describe(string engine)
    {
        var spec = Spec(engine);
        return UseLocal(spec) is { } local ? $"local {local}" : $"container {spec.ImageReference}";
    }

    public async Task<ToolOutput> RunAsync(
        string engine, IReadOnlyList<string> arguments, string sourcePath, string workPath,
        TimeSpan timeout, CancellationToken cancellationToken)
    {
        var spec = Spec(engine);
        var startInfo = new ProcessStartInfo
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };

        if (UseLocal(spec) is { } localPath)
        {
            startInfo.FileName = localPath;
            foreach (var argument in arguments)
            {
                startInfo.ArgumentList.Add(argument.Replace(SourceToken, sourcePath).Replace(WorkToken, workPath));
            }
        }
        else
        {
            startInfo.FileName = "docker";
            foreach (var argument in (string[])
            [
                "run", "--rm",
                "--network", "bridge",
                "-v", $"{sourcePath}:{ContainerSource}:ro",
                "-v", $"{workPath}:{ContainerWork}",
                spec.ImageReference,
            ])
            {
                startInfo.ArgumentList.Add(argument);
            }

            foreach (var argument in arguments)
            {
                startInfo.ArgumentList.Add(argument.Replace(SourceToken, ContainerSource).Replace(WorkToken, ContainerWork));
            }
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
            throw new TimeoutException($"{engine} did not finish within {timeout.TotalSeconds:0}s.");
        }

        return new ToolOutput(process.ExitCode, stdout.ToString(), stderr.ToString());
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
