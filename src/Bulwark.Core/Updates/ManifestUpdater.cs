namespace Bulwark.Core.Updates;

public enum UpdateStatus
{
    Updated,
    AlreadyCurrent,
    Rejected,
}

public sealed record UpdateResult(UpdateStatus Status, string Message, EngineManifest? Manifest = null);

/// <summary>
/// Fetches a newer signed manifest and installs it. Refuses anything that is unsigned,
/// signed with the wrong key, missing image digests, from an unknown schema, or older than
/// what is installed. Engines themselves are pulled lazily by digest at scan time.
/// </summary>
public sealed class ManifestUpdater(HttpClient http, ManifestStore store, string trustedPublicKeyPem)
{
    public async Task<UpdateResult> UpdateAsync(Uri manifestUrl, CancellationToken cancellationToken)
    {
        var manifestBytes = await http.GetByteArrayAsync(manifestUrl, cancellationToken);
        var signature = await http.GetStringAsync(new Uri(manifestUrl + ".sig"), cancellationToken);
        return Install(manifestBytes, signature);
    }

    /// <summary>Verifies and installs a manifest already on disk (air-gapped installs).</summary>
    public UpdateResult Install(byte[] manifestBytes, string signature)
    {
        if (!ManifestSignature.Verify(manifestBytes, signature, trustedPublicKeyPem))
        {
            return new UpdateResult(UpdateStatus.Rejected, "Signature check failed. The manifest was not installed.");
        }

        EngineManifest candidate;
        try
        {
            candidate = EngineManifest.Parse(manifestBytes);
        }
        catch (Exception e) when (e is System.Text.Json.JsonException or InvalidDataException)
        {
            return new UpdateResult(UpdateStatus.Rejected, $"Manifest is signed but not valid JSON: {e.Message}");
        }

        if (candidate.SchemaVersion > EngineManifest.CurrentSchemaVersion)
        {
            return new UpdateResult(UpdateStatus.Rejected,
                $"Manifest schema {candidate.SchemaVersion} needs a newer Bulwark. Update the Bulwark binary first.");
        }

        var unpinned = candidate.Engines.Where(e => string.IsNullOrWhiteSpace(e.Digest)).Select(e => e.Name).ToList();
        if (unpinned.Count > 0)
        {
            return new UpdateResult(UpdateStatus.Rejected, $"Engines without an image digest: {string.Join(", ", unpinned)}.");
        }

        var (current, isBuiltIn) = store.Load();
        if (!isBuiltIn && candidate.Sequence < current.Sequence)
        {
            return new UpdateResult(UpdateStatus.Rejected,
                $"Manifest sequence {candidate.Sequence} is older than installed {current.Sequence}; possible rollback attack.");
        }

        if (!isBuiltIn && candidate.Sequence == current.Sequence)
        {
            return new UpdateResult(UpdateStatus.AlreadyCurrent, $"Already on manifest {current.Sequence}.", current);
        }

        store.Save(manifestBytes, signature);
        return new UpdateResult(UpdateStatus.Updated, $"Installed manifest {candidate.Sequence} ({candidate.Channel}).", candidate);
    }
}
