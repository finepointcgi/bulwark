using System.Text;
using System.Text.Json;
using Nightjar.Core.Updates;

namespace Nightjar.Tests;

public sealed class UpdaterTests : IDisposable
{
    private readonly string _home = Directory.CreateTempSubdirectory("nightjar-home-").FullName;
    private readonly (string PrivateKeyPem, string PublicKeyPem) _keys = ManifestSignature.CreateKeyPair();

    public void Dispose() => Directory.Delete(_home, recursive: true);

    [Fact]
    public void Installs_a_valid_signed_manifest()
    {
        var (updater, store) = Create();
        var bytes = ManifestBytes(sequence: 5);

        var result = updater.Install(bytes, ManifestSignature.Sign(bytes, _keys.PrivateKeyPem));

        Assert.Equal(UpdateStatus.Updated, result.Status);
        var (installed, isBuiltIn) = store.Load();
        Assert.False(isBuiltIn);
        Assert.Equal(5, installed.Sequence);
    }

    [Fact]
    public void Rejects_tampered_manifest()
    {
        var (updater, store) = Create();
        var bytes = ManifestBytes(sequence: 5);
        var signature = ManifestSignature.Sign(bytes, _keys.PrivateKeyPem);
        var tampered = Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(bytes).Replace("v1.0.0", "v6.6.6"));

        Assert.Equal(UpdateStatus.Rejected, updater.Install(tampered, signature).Status);
        Assert.True(store.Load().IsBuiltIn);
    }

    [Fact]
    public void Rejects_manifest_signed_by_another_key()
    {
        var (updater, _) = Create();
        var bytes = ManifestBytes(sequence: 5);
        var attackerKey = ManifestSignature.CreateKeyPair().PrivateKeyPem;

        Assert.Equal(UpdateStatus.Rejected, updater.Install(bytes, ManifestSignature.Sign(bytes, attackerKey)).Status);
    }

    [Fact]
    public void Rejects_rollback_to_older_sequence()
    {
        var (updater, store) = Create();
        var newer = ManifestBytes(sequence: 7);
        var older = ManifestBytes(sequence: 3);

        updater.Install(newer, ManifestSignature.Sign(newer, _keys.PrivateKeyPem));
        var result = updater.Install(older, ManifestSignature.Sign(older, _keys.PrivateKeyPem));

        Assert.Equal(UpdateStatus.Rejected, result.Status);
        Assert.Equal(7, store.Load().Manifest.Sequence);
    }

    [Fact]
    public void Rejects_engines_without_image_digest()
    {
        var (updater, _) = Create();
        var bytes = ManifestBytes(sequence: 5, digest: null);

        var result = updater.Install(bytes, ManifestSignature.Sign(bytes, _keys.PrivateKeyPem));

        Assert.Equal(UpdateStatus.Rejected, result.Status);
        Assert.Contains("digest", result.Message);
    }

    private (ManifestUpdater, ManifestStore) Create()
    {
        var store = new ManifestStore(_home);
        return (new ManifestUpdater(new HttpClient(), store, _keys.PublicKeyPem), store);
    }

    private static byte[] ManifestBytes(long sequence, string? digest = "sha256:" + "a1b2c3d4" + "00000000000000000000000000000000000000000000000000000000")
    {
        var manifest = new EngineManifest
        {
            SchemaVersion = 1,
            Channel = "stable",
            Sequence = sequence,
            Published = DateTimeOffset.UnixEpoch,
            Engines = [new EngineSpec { Name = "syft", Version = "v1.0.0", Image = "docker.io/anchore/syft", Digest = digest, Binary = "syft" }],
        };
        return JsonSerializer.SerializeToUtf8Bytes(manifest, EngineManifest.JsonOptions);
    }
}
