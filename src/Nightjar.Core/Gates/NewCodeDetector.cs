using System.Diagnostics;
using System.Text.RegularExpressions;
using Nightjar.Core.Findings;
using Nightjar.Core.Reports;

namespace Nightjar.Core.Gates;

/// <summary>
/// Decides which findings a change introduced, so the quality gate can fail only on new problems
/// (SonarQube's "new code" idea). Without this, teams with existing debt switch the gate off.
/// </summary>
public static partial class NewCodeDetector
{
    /// <summary>New = not present in an earlier report of the same project (by stable fingerprint).</summary>
    public static IReadOnlySet<string> AgainstBaseline(IEnumerable<Finding> current, ScanReport baseline)
    {
        var old = baseline.Findings.Select(f => f.Id).ToHashSet(StringComparer.Ordinal);
        return current.Where(f => !old.Contains(f.Id)).Select(f => f.Id).ToHashSet(StringComparer.Ordinal);
    }

    /// <summary>
    /// New = on a line changed since <paramref name="gitRef"/> (compared from the merge base, as a PR
    /// would). Dependency findings count as new when that package version was not in the lockfile
    /// at the merge base. Findings without a location are treated as new, so nothing slips through.
    /// </summary>
    public static IReadOnlySet<string> SinceGitRef(IEnumerable<Finding> current, string repositoryRoot, string gitRef)
    {
        var mergeBase = Git(repositoryRoot, "merge-base", gitRef, "HEAD").Trim();
        var changed = ParseDiff(Git(repositoryRoot, "diff", "--unified=0", "--no-color", "--no-ext-diff", mergeBase));

        // Finding paths are relative to the scanned folder; git paths to the repository root.
        var prefix = (TryGit(repositoryRoot, "rev-parse", "--show-prefix") ?? "").Trim();
        var oldContents = new Dictionary<string, string?>(StringComparer.Ordinal);

        var result = new HashSet<string>(StringComparer.Ordinal);
        foreach (var finding in current)
        {
            if (finding.Location?.Path is not { } path)
            {
                result.Add(finding.Id);
                continue;
            }

            path = prefix + path.Replace('\\', '/');
            if (finding.Package is { } package)
            {
                if (!oldContents.TryGetValue(path, out var old))
                {
                    old = oldContents[path] = TryGit(repositoryRoot, "show", $"{mergeBase}:{path}");
                }

                if (old is null || !(old.Contains(package.Name, StringComparison.Ordinal) && old.Contains(package.Version, StringComparison.Ordinal)))
                {
                    result.Add(finding.Id);
                }

                continue;
            }

            if (changed.TryGetValue(path, out var lines)
                && (finding.Location.StartLine is not { } line || lines.Contains(line)))
            {
                result.Add(finding.Id);
            }
        }

        return result;
    }

    /// <summary>Changed line numbers (new side) per file. New files show up as one hunk covering every line.</summary>
    public static Dictionary<string, HashSet<int>> ParseDiff(string diff)
    {
        var files = new Dictionary<string, HashSet<int>>(StringComparer.Ordinal);
        HashSet<int>? currentFile = null;
        foreach (var line in diff.Split('\n'))
        {
            if (line.StartsWith("+++ ", StringComparison.Ordinal))
            {
                var name = line[4..].Trim();
                currentFile = name == "/dev/null" ? null : files[name.StartsWith("b/", StringComparison.Ordinal) ? name[2..] : name] = [];
                continue;
            }

            if (line.StartsWith("--- /dev/null", StringComparison.Ordinal))
            {
                continue; // The +++ line that follows names the new file; hunks below cover all its lines.
            }

            if (currentFile is not null && Hunk().Match(line) is { Success: true } match)
            {
                var start = int.Parse(match.Groups[1].Value, System.Globalization.CultureInfo.InvariantCulture);
                var count = match.Groups[2].Success ? int.Parse(match.Groups[2].Value, System.Globalization.CultureInfo.InvariantCulture) : 1;
                for (var i = 0; i < count; i++)
                {
                    currentFile.Add(start + i);
                }
            }
        }

        return files;
    }

    private static string Git(string root, params string[] args) =>
        TryGit(root, args) ?? throw new InvalidOperationException($"git {string.Join(' ', args)} failed in {root}. Is the ref fetched? (CI: use fetch-depth: 0)");

    private static string? TryGit(string root, params string[] args)
    {
        var start = new ProcessStartInfo("git") { RedirectStandardOutput = true, RedirectStandardError = true, WorkingDirectory = root };
        foreach (var arg in args)
        {
            start.ArgumentList.Add(arg);
        }

        using var process = Process.Start(start)!;
        var output = process.StandardOutput.ReadToEnd();
        process.StandardError.ReadToEnd();
        process.WaitForExit();
        return process.ExitCode == 0 ? output : null;
    }

    [GeneratedRegex(@"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")]
    private static partial Regex Hunk();
}
