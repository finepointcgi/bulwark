using Bulwark.Core.Findings;

namespace Bulwark.Core.Fixes;

/// <summary>One dependency upgrade that resolves one or more advisories.</summary>
public sealed record DependencyFix(
    PackageRef Package,
    string TargetVersion,
    string? ManifestPath,
    IReadOnlyList<string> Advisories,
    Severity WorstSeverity);

public sealed record FixPlan(IReadOnlyList<DependencyFix> Fixes, IReadOnlyList<(Finding Finding, string Reason)> Unfixable);

/// <summary>
/// Picks the smallest upgrade per package that fixes every open advisory against it. Smallest,
/// because large jumps break builds and reviewers reject them; all advisories, because fixing one
/// CVE while leaving another on the same package is a wasted PR.
/// </summary>
public static class FixPlanner
{
    public static FixPlan Plan(IEnumerable<Finding> findings, Severity minimum = Severity.Low)
    {
        var fixes = new List<DependencyFix>();
        var unfixable = new List<(Finding, string)>();

        var open = findings
            .Where(f => f.Category == FindingCategory.Vulnerability && f.Package is not null && f.Severity >= minimum)
            .Where(f => f.Triage is TriageState.New or TriageState.Confirmed);

        foreach (var group in open.GroupBy(f => (f.Package!.Ecosystem, f.Package.Name, f.Package.Version, f.Location?.Path)))
        {
            var current = group.Key.Version;
            string? target = null;
            var blocked = false;
            foreach (var finding in group)
            {
                var candidates = finding.FixedVersions.Where(v => Compare(v, current) > 0).ToList();
                if (candidates.Count == 0)
                {
                    unfixable.Add((finding, finding.FixedVersions.Count == 0 ? "no fixed version published yet" : "no fixed version above the installed one"));
                    blocked = true;
                    continue;
                }

                // Smallest fix for this advisory; the package target is the largest of those.
                var smallest = candidates.OrderBy(v => v, Comparer<string>.Create(Compare)).First();
                if (target is null || Compare(smallest, target) > 0)
                {
                    target = smallest;
                }
            }

            if (target is not null)
            {
                var first = group.First();
                fixes.Add(new DependencyFix(
                    first.Package!,
                    target,
                    group.Key.Path,
                    group.Select(f => f.RuleId).Distinct().ToList(),
                    group.Max(f => f.Severity)));
            }
            else if (!blocked)
            {
                unfixable.Add((group.First(), "no fixed version"));
            }
        }

        return new FixPlan(fixes.OrderByDescending(f => f.WorstSeverity).ThenBy(f => f.Package.Name, StringComparer.Ordinal).ToList(), unfixable);
    }

    /// <summary>
    /// Version order good enough for semver, PEP 440 release numbers, Go and NuGet:
    /// numeric parts compared numerically, a pre-release ("-rc1", "a1") sorts before its release.
    /// </summary>
    public static int Compare(string a, string b)
    {
        var (aParts, aPre) = Split(a);
        var (bParts, bPre) = Split(b);
        for (var i = 0; i < Math.Max(aParts.Length, bParts.Length); i++)
        {
            var x = i < aParts.Length ? aParts[i] : 0;
            var y = i < bParts.Length ? bParts[i] : 0;
            if (x != y)
            {
                return x.CompareTo(y);
            }
        }

        return (aPre, bPre) switch
        {
            (null, null) => 0,
            (null, _) => 1,
            (_, null) => -1,
            _ => string.CompareOrdinal(aPre, bPre),
        };
    }

    private static (long[] Parts, string? Pre) Split(string version)
    {
        var v = version.Trim().TrimStart('v', 'V').Split('+')[0];
        var dash = v.IndexOfAny(['-', 'a', 'b', 'r']);
        var numeric = dash > 0 && !char.IsDigit(v[dash]) ? v[..dash] : v;
        var pre = numeric.Length < v.Length ? v[numeric.Length..].TrimStart('-', '.') : null;
        var parts = numeric.Split('.').Select(p => long.TryParse(p, out var n) ? n : 0).ToArray();
        return (parts, string.IsNullOrEmpty(pre) ? null : pre);
    }
}
