using System.Text;
using Bulwark.Core.Engines;
using Bulwark.Core.Findings;

namespace Bulwark.Core.Ai;

/// <summary>One excerpt of project source shown to the model.</summary>
public sealed record EvidenceExcerpt(string Path, int StartLine, string Text);

/// <summary>
/// Finds the code an AI reviewer needs to judge a finding: the flagged location itself, and for
/// dependency vulnerabilities, the places the project actually uses the vulnerable package.
/// Purely lexical, so it is fast and deterministic; the model does the reasoning.
/// </summary>
public sealed class EvidenceCollector(string rootPath, int maxChars = 40_000, int maxFiles = 8)
{
    private const int LocationContextLines = 40;
    private const int UsageContextLines = 12;
    private const long MaxFileBytes = 512 * 1024;

    private List<string>? _sourceFiles;

    public IReadOnlyList<EvidenceExcerpt> Collect(Finding finding)
    {
        var excerpts = new List<EvidenceExcerpt>();
        var budget = maxChars;

        // The lines around a secret finding contain the secret itself. Never send them anywhere.
        if (finding.Category == FindingCategory.Secret)
        {
            return excerpts;
        }

        if (finding.Location?.Path is { } path && TryRead(path) is { } lines)
        {
            var center = finding.Location.StartLine ?? 1;
            Add(excerpts, ref budget, Excerpt(path, lines, [center], LocationContextLines));
        }

        if (finding.Package is { } package)
        {
            foreach (var token in UsageTokens(package))
            {
                foreach (var file in SourceFiles())
                {
                    if (excerpts.Count >= maxFiles || budget <= 0)
                    {
                        break;
                    }

                    if (excerpts.Any(e => e.Path == file) || TryRead(file) is not { } source)
                    {
                        continue;
                    }

                    var hits = new List<int>();
                    for (var i = 0; i < source.Length; i++)
                    {
                        if (source[i].Contains(token, StringComparison.Ordinal))
                        {
                            hits.Add(i + 1);
                        }
                    }

                    if (hits.Count > 0)
                    {
                        Add(excerpts, ref budget, Excerpt(file, source, hits.Take(5).ToList(), UsageContextLines));
                    }
                }
            }
        }

        return excerpts;
    }

    /// <summary>Strings that show up in source where a package is imported or called.</summary>
    internal static IEnumerable<string> UsageTokens(PackageRef package)
    {
        var name = package.Name;
        var tokens = new List<string> { name };

        // Maven "group:artifact" is imported by group; Go and npm scopes import the full path.
        if (name.Contains(':'))
        {
            tokens.Add(name.Split(':')[0]);
        }

        // PyPI distribution names often differ from import names only by '-' vs '_'.
        if (name.Contains('-'))
        {
            tokens.Add(name.Replace('-', '_'));
        }

        return tokens.Where(t => t.Length >= 3).Distinct(StringComparer.Ordinal);
    }

    private IEnumerable<string> SourceFiles() =>
        _sourceFiles ??= ProjectDetector.EnumerateFiles(rootPath)
            .Where(f => ProjectDetector.ExtensionLanguages.ContainsKey(Path.GetExtension(f)))
            .Select(f => Path.GetRelativePath(rootPath, f))
            .Order(StringComparer.Ordinal)
            .ToList();

    private string[]? TryRead(string relativePath)
    {
        var full = Path.GetFullPath(Path.Combine(rootPath, relativePath));

        // Never let a finding path (which came from engine output) read outside the scanned tree.
        var root = Path.GetFullPath(rootPath).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        if (!full.StartsWith(root, StringComparison.Ordinal))
        {
            return null;
        }

        try
        {
            var info = new FileInfo(full);
            return info.Exists && info.Length <= MaxFileBytes ? File.ReadAllLines(full) : null;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    private static EvidenceExcerpt Excerpt(string path, string[] lines, IReadOnlyList<int> centers, int context)
    {
        // Merge overlapping windows around each hit so one excerpt covers a cluster of uses.
        var windows = centers
            .Select(c => (Start: Math.Max(1, c - context), End: Math.Min(lines.Length, c + context)))
            .OrderBy(w => w.Start)
            .Aggregate(new List<(int Start, int End)>(), (merged, w) =>
            {
                if (merged.Count > 0 && w.Start <= merged[^1].End + 1)
                {
                    merged[^1] = (merged[^1].Start, Math.Max(merged[^1].End, w.End));
                }
                else
                {
                    merged.Add(w);
                }

                return merged;
            });

        var text = new StringBuilder();
        foreach (var (start, end) in windows)
        {
            if (text.Length > 0)
            {
                text.AppendLine("...");
            }

            for (var line = start; line <= end; line++)
            {
                text.Append(line).Append(": ").AppendLine(lines[line - 1]);
            }
        }

        return new EvidenceExcerpt(path, windows.Count > 0 ? windows[0].Start : 1, text.ToString());
    }

    private static void Add(List<EvidenceExcerpt> excerpts, ref int budget, EvidenceExcerpt excerpt)
    {
        if (budget <= 0)
        {
            return;
        }

        var text = excerpt.Text.Length > budget ? excerpt.Text[..budget] + "\n[truncated]\n" : excerpt.Text;
        excerpts.Add(excerpt with { Text = text });
        budget -= text.Length;
    }
}
