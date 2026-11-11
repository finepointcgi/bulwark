using System.Text;
using System.Text.RegularExpressions;
using Nightjar.Core.Findings;

namespace Nightjar.Core.Triage;

/// <summary>
/// <c>.nightjar/ignore</c>: gitignore-style path patterns whose findings are dropped (test fixtures,
/// vendored code, deliberately vulnerable samples). Committed with the code, so CI and developers
/// agree. Patterns: <c>*</c> within a folder, <c>**</c> across folders, a trailing <c>/</c> for a
/// folder, no slash = match the name anywhere, <c>#</c> comments.
/// </summary>
public sealed class IgnoreRules
{
    public const string FileName = ".nightjar/ignore";

    private readonly List<Regex> _patterns;

    private IgnoreRules(List<Regex> patterns) => _patterns = patterns;

    public static IgnoreRules Empty { get; } = new([]);

    public bool HasRules => _patterns.Count > 0;

    public static IgnoreRules Load(string project)
    {
        var path = Path.Combine(project, FileName);
        return File.Exists(path) ? Parse(File.ReadAllLines(path)) : Empty;
    }

    public static IgnoreRules Parse(IEnumerable<string> lines) =>
        new(lines.Select(l => l.Trim())
            .Where(l => l.Length > 0 && !l.StartsWith('#'))
            .Select(ToRegex)
            .ToList());

    public bool IsIgnored(Finding finding) =>
        finding.Location?.Path is { } path && IsIgnored(path);

    public bool IsIgnored(string path)
    {
        path = path.Replace('\\', '/').TrimStart('.', '/');
        return _patterns.Any(p => p.IsMatch(path));
    }

    private static Regex ToRegex(string pattern)
    {
        var directory = pattern.EndsWith('/');
        pattern = pattern.Trim('/');
        var anchored = pattern.Contains('/');

        var regex = new StringBuilder(anchored ? "^" : "(^|/)");
        for (var i = 0; i < pattern.Length; i++)
        {
            var c = pattern[i];
            if (c == '*' && i + 1 < pattern.Length && pattern[i + 1] == '*')
            {
                regex.Append(".*");
                i++;
                if (i + 1 < pattern.Length && pattern[i + 1] == '/')
                {
                    i++; // "**/" also matches zero folders
                    regex.Append("/?");
                }
            }
            else if (c == '*')
            {
                regex.Append("[^/]*");
            }
            else if (c == '?')
            {
                regex.Append("[^/]");
            }
            else
            {
                regex.Append(Regex.Escape(c.ToString()));
            }
        }

        // A folder pattern (or any pattern) also matches everything underneath it.
        regex.Append(directory ? "/" : "(/|$)");
        return new Regex(regex.ToString(), RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);
    }
}
