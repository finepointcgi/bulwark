using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace Nightjar.Core.Findings;

/// <summary>
/// Builds stable finding ids. The same issue must get the same id across scans
/// (so triage decisions stick) and across engines (so duplicates merge).
/// </summary>
public static partial class Fingerprint
{
    /// <summary>
    /// Vulnerability in a dependency. Keyed on the package and the canonical advisory id,
    /// never on file path, so moving a lockfile does not reset triage.
    /// </summary>
    public static string ForVulnerability(PackageRef package, string advisoryId, IEnumerable<string> aliases)
    {
        var canonical = CanonicalAdvisoryId(advisoryId, aliases);
        return Hash("vuln", package.Ecosystem.ToLowerInvariant(), package.Name.ToLowerInvariant(), package.Version, canonical);
    }

    /// <summary>License issue for one package version.</summary>
    public static string ForLicense(PackageRef package, string license) =>
        Hash("license", package.Ecosystem.ToLowerInvariant(), package.Name.ToLowerInvariant(), package.Version, license.ToUpperInvariant());

    /// <summary>
    /// Code-level finding (SAST, secrets, IaC). Keyed on rule, file and the normalized
    /// code snippet rather than the line number, so unrelated edits above it do not change the id.
    /// </summary>
    public static string ForCode(string ruleId, string path, string? snippet, int? line)
    {
        var normalizedPath = path.Replace('\\', '/').TrimStart('.', '/');
        var anchor = string.IsNullOrWhiteSpace(snippet) ? $"line:{line}" : NormalizeSnippet(snippet);
        return Hash("code", ruleId, normalizedPath, anchor);
    }

    /// <summary>
    /// Finding from active testing. Keyed on rule, method, the URL without query values (query
    /// parameter names are kept, sorted) and the affected parameter, so re-tests produce the same id.
    /// </summary>
    public static string ForDynamic(string ruleId, string method, Uri uri, string? parameter)
    {
        var query = uri.Query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries)
            .Select(pair => pair.Split('=', 2)[0])
            .Distinct(StringComparer.Ordinal)
            .Order(StringComparer.Ordinal);
        var location = $"{uri.Scheme}://{uri.Host.ToLowerInvariant()}:{uri.Port}{uri.AbsolutePath}?{string.Join('&', query)}";
        return Hash("dynamic", ruleId, method.ToUpperInvariant(), location, parameter ?? "");
    }

    /// <summary>
    /// Prefer a CVE id, then GHSA, then whatever the engine gave, so two engines that
    /// report the same CVE under different ids still produce one fingerprint.
    /// </summary>
    public static string CanonicalAdvisoryId(string advisoryId, IEnumerable<string> aliases)
    {
        var all = aliases.Prepend(advisoryId).Select(a => a.Trim().ToUpperInvariant()).ToList();
        return all.Where(a => a.StartsWith("CVE-", StringComparison.Ordinal)).Order(StringComparer.Ordinal).FirstOrDefault()
            ?? all.Where(a => a.StartsWith("GHSA-", StringComparison.Ordinal)).Order(StringComparer.Ordinal).FirstOrDefault()
            ?? all[0];
    }

    internal static string NormalizeSnippet(string snippet) => Whitespace().Replace(snippet, " ").Trim();

    private static string Hash(params string[] parts)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(string.Join('\u001f', parts)));
        return Convert.ToHexStringLower(bytes)[..32];
    }

    [GeneratedRegex(@"\s+")]
    private static partial Regex Whitespace();
}
