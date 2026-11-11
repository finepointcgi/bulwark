using System.Text.Json;
using System.Text.RegularExpressions;

namespace Bulwark.Engines.Syft;

/// <summary>
/// Names of the packages the scanned project itself defines. Syft lists the project as a
/// component of its own SBOM, which made every project report "no license detected" for itself.
/// </summary>
public static partial class OwnPackages
{
    public static IReadOnlySet<string> Find(string root, IEnumerable<string> manifests)
    {
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var relative in manifests)
        {
            var path = Path.Combine(root, relative);
            var file = Path.GetFileName(path);
            try
            {
                switch (file)
                {
                    case "package.json":
                        using (var doc = JsonDocument.Parse(File.ReadAllText(path)))
                        {
                            if (doc.RootElement.TryGetProperty("name", out var name) && name.ValueKind == JsonValueKind.String)
                            {
                                names.Add(name.GetString()!);
                            }
                        }

                        break;
                    case "package-lock.json":
                        using (var doc = JsonDocument.Parse(File.ReadAllText(path)))
                        {
                            if (doc.RootElement.TryGetProperty("name", out var name) && name.ValueKind == JsonValueKind.String)
                            {
                                names.Add(name.GetString()!);
                            }
                        }

                        break;
                    case "go.mod" when GoModule().Match(File.ReadAllText(path)) is { Success: true } m:
                        names.Add(m.Groups[1].Value);
                        break;
                    case "Cargo.toml" or "pyproject.toml" when TomlName().Match(File.ReadAllText(path)) is { Success: true } m:
                        names.Add(m.Groups[1].Value);
                        break;
                    default:
                        if (file.EndsWith(".csproj", StringComparison.OrdinalIgnoreCase) || file.EndsWith(".fsproj", StringComparison.OrdinalIgnoreCase))
                        {
                            names.Add(Path.GetFileNameWithoutExtension(file));
                        }

                        break;
                }
            }
            catch (Exception e) when (e is IOException or JsonException or UnauthorizedAccessException)
            {
                // Unreadable manifest: worst case the project's own package gets a license finding.
            }
        }

        return names;
    }

    [GeneratedRegex(@"(?m)^module\s+(\S+)")]
    private static partial Regex GoModule();

    [GeneratedRegex(@"(?ms)^\[(?:package|project|tool\.poetry)\][^\[]*?^name\s*=\s*[""']([^""']+)[""']")]
    private static partial Regex TomlName();
}
