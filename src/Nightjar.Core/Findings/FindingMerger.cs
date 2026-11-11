namespace Nightjar.Core.Findings;

/// <summary>Merges findings that share a fingerprint into one, keeping the most informative data.</summary>
public static class FindingMerger
{
    public static IReadOnlyList<Finding> Merge(IEnumerable<Finding> findings) =>
        findings
            .GroupBy(f => f.Id)
            .Select(group => group.Aggregate(MergePair))
            .OrderByDescending(f => f.Severity)
            .ThenBy(f => f.Title, StringComparer.Ordinal)
            .ToList();

    private static Finding MergePair(Finding a, Finding b) => a with
    {
        // Engines disagree on severity sometimes; report the worst so nothing is understated.
        Severity = a.Severity >= b.Severity ? a.Severity : b.Severity,
        Description = a.Description ?? b.Description,
        Location = a.Location ?? b.Location,
        Assessment = a.Assessment ?? b.Assessment,
        Engines = Union(a.Engines, b.Engines),
        Aliases = Union(a.Aliases, b.Aliases),
        FixedVersions = Union(a.FixedVersions, b.FixedVersions),
        References = Union(a.References, b.References),
    };

    private static List<string> Union(IEnumerable<string> a, IEnumerable<string> b) =>
        a.Concat(b).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
}
