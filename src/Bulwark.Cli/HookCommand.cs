using System.Diagnostics;
using Bulwark.Core.Engines;
using Bulwark.Core.Findings;
using Bulwark.Core.Updates;

namespace Bulwark.Cli;

/// <summary>
/// bulwark hook install|uninstall   — manage a git pre-commit hook in the current repository
/// bulwark precommit                — what the hook runs: scan staged content for secrets, block the commit if any
/// Only the staged version of each file is scanned (not your working copy), so what is checked is what gets committed.
/// </summary>
internal static class HookCommand
{
    private const string Marker = "# bulwark-pre-commit";

    public static int Hook(Options options)
    {
        var action = options.Positional.FirstOrDefault();
        var hooks = GitOutput(".", "rev-parse", "--git-path", "hooks")?.Trim();
        if (hooks is null || action is not ("install" or "uninstall"))
        {
            Console.Error.WriteLine("usage: bulwark hook install|uninstall   (run inside a git repository)");
            return Cli.ExitError;
        }

        var path = Path.Combine(hooks, "pre-commit");
        var existing = File.Exists(path) ? File.ReadAllText(path) : null;
        if (action == "uninstall")
        {
            if (existing?.Contains(Marker, StringComparison.Ordinal) == true) { File.Delete(path); Console.Error.WriteLine("Removed pre-commit hook."); }
            else { Console.Error.WriteLine("No Bulwark pre-commit hook installed."); }
            return Cli.ExitPassed;
        }

        if (existing is not null && !existing.Contains(Marker, StringComparison.Ordinal))
        {
            Console.Error.WriteLine($"error: {path} already exists and is not Bulwark's. Add `bulwark precommit` to it yourself, or use the pre-commit framework (see .pre-commit-hooks.yaml).");
            return Cli.ExitError;
        }

        Directory.CreateDirectory(hooks);
        File.WriteAllText(path, $"#!/bin/sh\n{Marker}\nexec bulwark precommit\n");
        File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute | UnixFileMode.GroupRead | UnixFileMode.GroupExecute | UnixFileMode.OtherRead | UnixFileMode.OtherExecute);
        Console.Error.WriteLine($"Installed {path}. Bypass in an emergency with: git commit --no-verify");
        return Cli.ExitPassed;
    }

    public static async Task<int> PreCommitAsync(Options options)
    {
        var staged = GitOutput(".", "diff", "--cached", "--name-only", "--diff-filter=ACM", "-z");
        if (staged is null)
        {
            Console.Error.WriteLine("error: not a git repository.");
            return Cli.ExitError;
        }

        var files = staged.Split('\0', StringSplitOptions.RemoveEmptyEntries);
        if (files.Length == 0)
        {
            return Cli.ExitPassed;
        }

        var snapshot = Directory.CreateTempSubdirectory("bulwark-staged-").FullName;
        try
        {
            foreach (var file in files)
            {
                var content = GitBytes(".", "show", $":{file}");
                if (content is null) { continue; }
                var target = Path.GetFullPath(Path.Combine(snapshot, file));
                if (!target.StartsWith(snapshot + Path.DirectorySeparatorChar, StringComparison.Ordinal)) { continue; }
                Directory.CreateDirectory(Path.GetDirectoryName(target)!);
                File.WriteAllBytes(target, content);
            }

            var store = ManifestStore.Default();
            var (manifest, _) = store.Load();
            var engines = EngineFactory.Create(EngineFactory.Runner(manifest, options), options)
                .Where(e => e.Name.Equals("gitleaks", StringComparison.OrdinalIgnoreCase)).ToArray();
            var report = await new ScanPipeline(engines, manifest).RunAsync(snapshot, null, CancellationToken.None);

            if (report.Engines.Any(e => !e.Succeeded))
            {
                // Fail open on tooling problems so a broken scanner never blocks all commits, but say so.
                Console.Error.WriteLine($"bulwark: secret scan could not run ({report.Engines.First(e => !e.Succeeded).Error}); commit allowed.");
                return Cli.ExitPassed;
            }

            var secrets = report.Findings.Where(f => f.Category == FindingCategory.Secret).ToList();
            if (secrets.Count == 0)
            {
                return Cli.ExitPassed;
            }

            Console.Error.WriteLine($"bulwark: {secrets.Count} possible secret(s) in staged changes — commit blocked:");
            foreach (var s in secrets)
            {
                Console.Error.WriteLine($"  {s.Location?.Path}:{s.Location?.StartLine}  {s.Title}");
            }

            Console.Error.WriteLine("Remove the secret (and rotate it if it was ever pushed), or commit with --no-verify if this is a false positive.");
            return Cli.ExitGateFailed;
        }
        finally
        {
            try { Directory.Delete(snapshot, recursive: true); } catch (IOException) { }
        }
    }

    private static string? GitOutput(string directory, params string[] args) =>
        GitBytes(directory, args) is { } bytes ? System.Text.Encoding.UTF8.GetString(bytes) : null;

    private static byte[]? GitBytes(string directory, params string[] args)
    {
        var start = new ProcessStartInfo("git") { WorkingDirectory = directory, RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (var a in args) { start.ArgumentList.Add(a); }
        try
        {
            using var process = Process.Start(start)!;
            using var memory = new MemoryStream();
            process.StandardOutput.BaseStream.CopyTo(memory);
            process.WaitForExit();
            return process.ExitCode == 0 ? memory.ToArray() : null;
        }
        catch (System.ComponentModel.Win32Exception)
        {
            return null;
        }
    }
}
