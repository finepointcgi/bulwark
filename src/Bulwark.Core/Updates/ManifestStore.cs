namespace Bulwark.Core.Updates;

/// <summary>
/// Local copy of the engine manifest (the lockfile every scan runs against).
/// Lives in ~/.bulwark by default, or BULWARK_HOME if set. The previously installed manifest
/// is kept next to it so a failed canary can roll back.
/// </summary>
public sealed class ManifestStore(string homeDirectory)
{
    public string HomeDirectory { get; } = homeDirectory;
    public string ManifestPath => Path.Combine(HomeDirectory, "manifest.json");
    public string SignaturePath => ManifestPath + ".sig";
    public string PreviousManifestPath => Path.Combine(HomeDirectory, "manifest.previous.json");
    private string PreviousSignaturePath => PreviousManifestPath + ".sig";
    private string LastCheckPath => Path.Combine(HomeDirectory, "last-update-check");

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

        if (File.Exists(ManifestPath))
        {
            File.Copy(ManifestPath, PreviousManifestPath, overwrite: true);
            if (File.Exists(SignaturePath))
            {
                File.Copy(SignaturePath, PreviousSignaturePath, overwrite: true);
            }
        }
        else
        {
            // First install: "previous" is the built-in set, so rolling back means deleting the file.
            File.Delete(PreviousManifestPath);
            File.Delete(PreviousSignaturePath);
        }

        // Write to temp files and move into place so a crash never leaves a half-written lockfile.
        var tempManifest = ManifestPath + ".tmp";
        var tempSignature = SignaturePath + ".tmp";
        File.WriteAllBytes(tempManifest, manifestBytes);
        File.WriteAllText(tempSignature, signature);
        File.Move(tempSignature, SignaturePath, overwrite: true);
        File.Move(tempManifest, ManifestPath, overwrite: true);
    }

    /// <summary>
    /// Restores the manifest that was installed before the last <see cref="Save"/>. The rolled-back
    /// sequence is remembered so the same bad manifest is not reinstalled on the next check.
    /// </summary>
    public void RollBack(long rejectedSequence)
    {
        if (File.Exists(PreviousManifestPath))
        {
            File.Copy(PreviousManifestPath, ManifestPath, overwrite: true);
            if (File.Exists(PreviousSignaturePath))
            {
                File.Copy(PreviousSignaturePath, SignaturePath, overwrite: true);
            }
        }
        else
        {
            File.Delete(ManifestPath);
            File.Delete(SignaturePath);
        }

        Directory.CreateDirectory(HomeDirectory);
        File.AppendAllText(Path.Combine(HomeDirectory, "rejected-sequences"), $"{rejectedSequence}\n");
    }

    public bool WasRejected(long sequence)
    {
        var path = Path.Combine(HomeDirectory, "rejected-sequences");
        return File.Exists(path) && File.ReadLines(path).Any(l => l.Trim() == sequence.ToString(System.Globalization.CultureInfo.InvariantCulture));
    }

    /// <summary>True when the last automatic update check is older than <paramref name="interval"/>.</summary>
    public bool IsUpdateCheckDue(TimeSpan interval) =>
        !File.Exists(LastCheckPath) || DateTime.UtcNow - File.GetLastWriteTimeUtc(LastCheckPath) > interval;

    public void MarkUpdateChecked()
    {
        Directory.CreateDirectory(HomeDirectory);
        File.WriteAllText(LastCheckPath, DateTimeOffset.UtcNow.ToString("O"));
    }
}

/// <summary>
/// Fallback used before the first update, built from the engines.json compiled into Bulwark.
/// Tags only (no digests), so scans print a warning until a signed manifest is installed.
/// </summary>
public static class BuiltInManifest
{
    public static readonly EngineManifest Value = EngineCatalog.Embedded().ToManifest(
        sequence: 0, channel: "builtin", published: new DateTimeOffset(2026, 11, 11, 0, 0, 0, TimeSpan.Zero));
}
