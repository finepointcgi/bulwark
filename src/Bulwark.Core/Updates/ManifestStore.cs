namespace Bulwark.Core.Updates;

/// <summary>
/// Local copy of the engine manifest (the lockfile every scan runs against).
/// Lives in ~/.bulwark by default, or BULWARK_HOME if set.
/// </summary>
public sealed class ManifestStore(string homeDirectory)
{
    public string HomeDirectory { get; } = homeDirectory;
    public string ManifestPath => Path.Combine(HomeDirectory, "manifest.json");
    public string SignaturePath => ManifestPath + ".sig";

    public static ManifestStore Default() => new(
        Environment.GetEnvironmentVariable("BULWARK_HOME")
        ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".bulwark"));

    /// <summary>Installed manifest, or the built-in defaults if the user has never run an update.</summary>
    public (EngineManifest Manifest, bool IsBuiltIn) Load()
    {
        if (File.Exists(ManifestPath))
        {
            return (EngineManifest.Parse(File.ReadAllBytes(ManifestPath)), false);
        }

        return (BuiltInManifest.Value, true);
    }

    public void Save(byte[] manifestBytes, string signature)
    {
        Directory.CreateDirectory(HomeDirectory);

        // Write to temp files and move into place so a crash never leaves a half-written lockfile.
        var tempManifest = ManifestPath + ".tmp";
        var tempSignature = SignaturePath + ".tmp";
        File.WriteAllBytes(tempManifest, manifestBytes);
        File.WriteAllText(tempSignature, signature);
        File.Move(tempSignature, SignaturePath, overwrite: true);
        File.Move(tempManifest, ManifestPath, overwrite: true);
    }
}

/// <summary>
/// Fallback used before the first update. Tags only (no digests), so scans print a warning
/// until a signed manifest is installed with <c>bulwark update</c>.
/// </summary>
public static class BuiltInManifest
{
    public static readonly EngineManifest Value = new()
    {
        SchemaVersion = EngineManifest.CurrentSchemaVersion,
        Channel = "builtin",
        Sequence = 0,
        Published = new DateTimeOffset(2026, 11, 11, 0, 0, 0, TimeSpan.Zero),
        Engines =
        [
            new EngineSpec { Name = "syft", Version = "v1.18.1", Image = "docker.io/anchore/syft", Binary = "syft" },
            new EngineSpec { Name = "osv-scanner", Version = "v2.0.0", Image = "ghcr.io/google/osv-scanner", Binary = "osv-scanner" },
            new EngineSpec { Name = "gitleaks", Version = "v8.30.1", Image = "ghcr.io/gitleaks/gitleaks", Binary = "gitleaks" },

            // No upstream image; built from the pinned release binary by engines/opengrep/Dockerfile.
            new EngineSpec { Name = "opengrep", Version = "v1.33.1", Image = "bulwark-engines/opengrep", Binary = "opengrep" },
        ],
    };
}
