using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Bulwark.Core.Findings;
using Bulwark.Engines.Execution;

namespace Bulwark.Engines.Gitleaks;

/// <summary>Maps the gitleaks JSON report to findings without ever keeping the secret itself.</summary>
public static class GitleaksParser
{
    public static IReadOnlyList<Finding> Parse(string json, string sourcePath, string engine)
    {
        using var document = JsonDocument.Parse(json);
        var findings = new List<Finding>();
        if (document.RootElement.ValueKind != JsonValueKind.Array)
        {
            return findings;
        }

        foreach (var leak in document.RootElement.EnumerateArray())
        {
            var rule = Str(leak, "RuleID") ?? "secret";
            var path = ToolRunner.ToProjectPath(Str(leak, "File") ?? "", sourcePath);
            var line = leak.TryGetProperty("StartLine", out var l) && l.TryGetInt32(out var n) ? n : (int?)null;
            var secret = Str(leak, "Secret") ?? "";

            // Hash of the secret value: the same leaked key gets the same id even if the line moves,
            // and rotating the key (new value) creates a new finding.
            var secretHash = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(secret)))[..16];

            findings.Add(new Finding
            {
                Id = Fingerprint.ForCode($"secret/{rule}", path, $"secret:{secretHash}", line),
                Category = FindingCategory.Secret,
                Severity = rule.Contains("private-key", StringComparison.OrdinalIgnoreCase) ? Severity.Critical : Severity.High,
                RuleId = $"secret/{rule}",
                Title = $"Hard-coded secret ({rule}) in {path}",
                Description = $"{Str(leak, "Description") ?? "Possible secret."} Value starts with {Mask(secret)}. "
                    + "Rotate the credential first; removing it from the code does not remove it from git history.",
                Location = new SourceLocation(path, line, null, null),
                Engines = [engine],
            });
        }

        return findings;
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
