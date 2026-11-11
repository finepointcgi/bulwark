using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Nightjar.Core.Findings;
using Nightjar.Engines.Execution;

namespace Nightjar.Engines.Gitleaks;

/// <summary>A leak plus the commit it came from (history scans only).</summary>
public sealed record SecretLeak(Finding Finding, string? Commit, DateTimeOffset? CommitDate);

/// <summary>Maps the gitleaks JSON report to findings without ever keeping the secret itself.</summary>
public static class GitleaksParser
{
    private const string RotateAdvice =
        "Rotate the credential first; removing it from the code does not remove it from git history.";

    public static IReadOnlyList<Finding> Parse(string json, string sourcePath, string engine) =>
        ParseLeaks(json, sourcePath, engine).Select(l => l.Finding).ToList();

    public static IReadOnlyList<SecretLeak> ParseLeaks(string json, string sourcePath, string engine)
    {
        using var document = JsonDocument.Parse(json);
        var leaks = new List<SecretLeak>();
        if (document.RootElement.ValueKind != JsonValueKind.Array)
        {
            return leaks;
        }

        foreach (var leak in document.RootElement.EnumerateArray())
        {
            var rule = Str(leak, "RuleID") ?? "secret";
            var path = ToolRunner.ToProjectPath(Str(leak, "File") ?? "", sourcePath);
            var line = leak.TryGetProperty("StartLine", out var l) && l.TryGetInt32(out var n) ? n : (int?)null;
            var secret = Str(leak, "Secret") ?? "";

            // Hash of the secret value: the same leaked key gets the same id even if the line moves,
            // and a working-tree hit merges with the matching history hit. Rotating the key
            // (new value) creates a new finding.
            var secretHash = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(secret)))[..16];

            var finding = new Finding
            {
                Id = Fingerprint.ForCode($"secret/{rule}", path, $"secret:{secretHash}", line),
                Category = FindingCategory.Secret,
                Severity = rule.Contains("private-key", StringComparison.OrdinalIgnoreCase) ? Severity.Critical : Severity.High,
                RuleId = $"secret/{rule}",
                Title = $"Hard-coded secret ({rule}) in {path}",
                Description = $"{Str(leak, "Description") ?? "Possible secret."} Value starts with {Mask(secret)}. {RotateAdvice}",
                Location = new SourceLocation(path, line, null, null),
                Engines = [engine],
            };

            var commit = Str(leak, "Commit") is { Length: > 0 } c ? c : null;
            var date = Str(leak, "Date") is { } d && DateTimeOffset.TryParse(d, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var parsed)
                ? parsed
                : (DateTimeOffset?)null;

            // Author name and email are deliberately dropped: they are personal data and not needed to fix the leak.
            leaks.Add(new SecretLeak(finding, commit, date));
        }

        return leaks;
    }

    /// <summary>
    /// Combines working-tree and history results. A secret in both becomes one finding that notes
    /// when it was first committed; a secret only in history gets its own finding, because it was
    /// "removed" but is still readable by anyone with a clone.
    /// </summary>
    public static IReadOnlyList<Finding> Combine(IReadOnlyList<Finding> workingTree, IReadOnlyList<SecretLeak> history)
    {
        var results = workingTree.ToDictionary(f => f.Id);
        foreach (var group in history.GroupBy(h => h.Finding.Id))
        {
            var first = group.OrderBy(h => h.CommitDate ?? DateTimeOffset.MaxValue).First();
            var since = Describe(first);

            if (results.TryGetValue(group.Key, out var current))
            {
                results[group.Key] = current with { Description = $"{current.Description} In git history since {since}." };
                continue;
            }

            var finding = first.Finding;
            var path = finding.Location?.Path ?? "";
            results[group.Key] = finding with
            {
                Title = $"Secret in git history ({finding.RuleId["secret/".Length..]}) in {path}",
                Description = $"Committed in {since} and no longer in the current files, but anyone with a clone can still read it. "
                    + $"Value starts with {MaskFrom(finding.Description)}. Rotate the credential; rewriting history "
                    + "(git filter-repo) only helps after rotation and once every clone is replaced.",
            };
        }

        return results.Values.ToList();
    }

    private static string Describe(SecretLeak leak)
    {
        var commit = leak.Commit is { Length: >= 7 } c ? $"commit {c[..7]}" : "an earlier commit";
        return leak.CommitDate is { } date ? $"{commit} ({date:yyyy-MM-dd})" : commit;
    }

    private static string MaskFrom(string? description)
    {
        const string marker = "Value starts with ";
        var start = description?.IndexOf(marker, StringComparison.Ordinal) ?? -1;
        if (start < 0)
        {
            return "****";
        }

        var rest = description![(start + marker.Length)..];
        var end = rest.IndexOf(". ", StringComparison.Ordinal);
        return end < 0 ? rest : rest[..end];
    }

    /// <summary>Shows at most the first 4 characters (enough to recognize the key type, e.g. "ghp_" or "AKIA").</summary>
    internal static string Mask(string secret) => secret.Length switch
    {
        0 => "(empty)",
        <= 8 => "****",
        _ => secret[..4] + "****",
    };

    private static string? Str(JsonElement element, string property) =>
        element.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;
}
