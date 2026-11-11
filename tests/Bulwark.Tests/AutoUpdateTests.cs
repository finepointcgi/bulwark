using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Bulwark.Core.Updates;
using Bulwark.Engines.Canary;

namespace Bulwark.Tests;

public sealed class AutoUpdateTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("bulwark-update-").FullName;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    [Fact]
    public void Embedded_catalog_builds_the_builtin_manifest()
    {
        var manifest = BuiltInManifest.Value;

        Assert.Equal("builtin", manifest.Channel);
        Assert.Equal("v1.33.1", manifest.Find("opengrep")!.Version);
        Assert.Equal("0.76.1", manifest.Find("trivy")!.Version); // {bare} strips the v
        Assert.Equal("bulwark-engines/opengrep:v1.33.1", manifest.Find("opengrep")!.ImageReference);
        Assert.All(manifest.Engines, e => Assert.Null(e.Digest));
    }

    [Fact]
    public void Generated_manifest_uses_registry_prefix_and_digests_for_self_built_images()
    {
        var digests = BuiltInManifest.Value.Engines.ToDictionary(e => e.Name, _ => "sha256:" + new string('a', 64));
        var manifest = EngineCatalog.Embedded().ToManifest(42, "stable", DateTimeOffset.UnixEpoch, digests, "ghcr.io/acme/bulwark-engines");

        Assert.Equal("ghcr.io/acme/bulwark-engines/opengrep@sha256:" + new string('a', 64), manifest.Find("opengrep")!.ImageReference);
        Assert.Equal("ghcr.io/aquasecurity/trivy", manifest.Find("trivy")!.Image); // upstream images keep their name
    }

    [Theory]
    [InlineData("v1.34.0", "v1.33.1", true)]
    [InlineData("v1.33.1", "v1.34.0", false)]
    [InlineData("0.77.0", "v0.76.1", true)]
    [InlineData("v2.0.0", "v2.0.0", false)]
    public void Watcher_only_moves_forward(string candidate, string current, bool expected) =>
        Assert.Equal(expected, EngineWatcher.IsNewer(candidate, current));

    [Fact]
    public async Task Watcher_bumps_to_newest_mature_release_and_rewrites_dockerfile()
    {
        var root = _dir;
        Directory.CreateDirectory(Path.Combine(root, "engines", "tool"));
        var dockerfile = Path.Combine(root, "engines", "tool", "Dockerfile");
        File.WriteAllText(dockerfile, "FROM base/tool:v1.0.0\nARG VERSION=v1.0.0\nARG SHA=old\nRUN true\n");

        var catalog = EngineCatalog.Parse("""
            {"engines":[{"name":"tool","binary":"tool","image":"bulwark-engines/tool","build":"engines/tool",
              "upstream":[{"repo":"acme/tool","tag":"v1.0.0","version":"{tag}",
                "dockerfile":{"FROM":"base/tool:{tag}","VERSION":"{tag}","SHA":"asset-sha256:tool_linux"}}]}]}
            """);

        var now = DateTimeOffset.UtcNow;
        var releases = JsonSerializer.Serialize(new object[]
        {
            Release("v1.3.0", now.AddDays(-2), prerelease: false),   // too new: inside the maturity window
            Release("v1.2.0-rc1", now.AddDays(-40), prerelease: true),
            Release("v1.2.0", now.AddDays(-20), prerelease: false),  // ← expected
            Release("v1.1.0", now.AddDays(-60), prerelease: false),
        });
        using var http = new HttpClient(new FakeHandler(_ => releases));

        var (updated, changes) = await new EngineWatcher(http, TimeSpan.FromDays(14)).CheckAsync(catalog, root, write: true, CancellationToken.None);

        var change = Assert.Single(changes);
        Assert.Equal(("v1.0.0", "v1.2.0"), (change.From, change.To));
        Assert.Equal("v1.2.0", updated.Engines[0].Version);
        Assert.Equal("FROM base/tool:v1.2.0\nARG VERSION=v1.2.0\nARG SHA=" + new string('b', 64) + "\nRUN true\n", File.ReadAllText(dockerfile));

        static object Release(string tag, DateTimeOffset published, bool prerelease) => new Dictionary<string, object?>
        {
            ["tag_name"] = tag, ["draft"] = false, ["prerelease"] = prerelease, ["published_at"] = published,
            ["assets"] = new[] { new Dictionary<string, string> { ["name"] = "tool_linux", ["digest"] = "sha256:" + new string('b', 64), ["browser_download_url"] = "https://x/tool" } },
        };
    }

    [Fact]
    public void Rollback_restores_previous_manifest_and_skips_the_bad_one_afterwards()
    {
        var keys = ManifestSignature.CreateKeyPair();
        var store = new ManifestStore(_dir);
        var updater = new ManifestUpdater(new HttpClient(), store, keys.PublicKeyPem);

        var good = Signed(5, keys.PrivateKeyPem);
        var bad = Signed(6, keys.PrivateKeyPem);
        Assert.Equal(UpdateStatus.Updated, updater.Install(good.Bytes, good.Signature).Status);
        Assert.Equal(UpdateStatus.Updated, updater.Install(bad.Bytes, bad.Signature).Status);

        store.RollBack(6);

        Assert.Equal(5, store.Load().Manifest.Sequence);
        Assert.Equal(UpdateStatus.AlreadyCurrent, updater.Install(bad.Bytes, bad.Signature).Status);
        var newer = Signed(7, keys.PrivateKeyPem);
        Assert.Equal(UpdateStatus.Updated, updater.Install(newer.Bytes, newer.Signature).Status);
    }

    [Fact]
    public void Rollback_after_first_install_returns_to_builtin()
    {
        var keys = ManifestSignature.CreateKeyPair();
        var store = new ManifestStore(_dir);
        var first = Signed(1, keys.PrivateKeyPem);
        new ManifestUpdater(new HttpClient(), store, keys.PublicKeyPem).Install(first.Bytes, first.Signature);

        store.RollBack(1);

        Assert.True(store.Load().IsBuiltIn);
    }

    [Fact]
    public async Task Self_update_refuses_a_binary_whose_hash_does_not_match()
    {
        var exe = Path.Combine(_dir, "bulwark");
        File.WriteAllText(exe, "old");
        var manifest = BuiltInManifest.Value with
        {
            Bulwark = new BulwarkRelease
            {
                Version = "9.9.9",
                Assets = [new BulwarkAsset(System.Runtime.InteropServices.RuntimeInformation.RuntimeIdentifier, "https://example.invalid/b", new string('0', 64))],
            },
        };
        using var http = new HttpClient(new FakeHandler(_ => "tampered binary"));

        var result = await new SelfUpdater(http).UpdateAsync(manifest, "0.1.0", exe, CancellationToken.None);

        Assert.False(result.Updated);
        Assert.Equal("old", File.ReadAllText(exe));
        Assert.Single(Directory.GetFiles(_dir)); // no leftover download
    }

    [Fact]
    public async Task Self_update_replaces_binary_when_hash_matches()
    {
        var exe = Path.Combine(_dir, "bulwark");
        File.WriteAllText(exe, "old");
        const string payload = "new binary";
        var sha = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(payload)));
        var manifest = BuiltInManifest.Value with
        {
            Bulwark = new BulwarkRelease
            {
                Version = "0.2.0",
                Assets = [new BulwarkAsset(System.Runtime.InteropServices.RuntimeInformation.RuntimeIdentifier, "https://example.invalid/b", sha)],
            },
        };
        using var http = new HttpClient(new FakeHandler(_ => payload));

        var result = await new SelfUpdater(http).UpdateAsync(manifest, "0.1.0", exe, CancellationToken.None);

        Assert.True(result.Updated);
        Assert.Equal(payload, File.ReadAllText(exe));
    }

    [Fact]
    public void Canary_corpus_extracts_with_a_fresh_token()
    {
        var root = CanaryCheck.ExtractCorpus();
        try
        {
            Assert.True(File.Exists(Path.Combine(root, "src", "Db.cs")));
            Assert.True(File.Exists(Path.Combine(root, "infra", "main.tf")));
            Assert.True(File.Exists(Path.Combine(root, "package-lock.json")));
            Assert.Matches(@"^GITHUB_TOKEN=ghp_[A-Za-z0-9]{36}\n$", File.ReadAllText(Path.Combine(root, "src", "settings.env")));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private static (byte[] Bytes, string Signature) Signed(long sequence, string privateKey)
    {
        var manifest = BuiltInManifest.Value with
        {
            Sequence = sequence,
            Engines = BuiltInManifest.Value.Engines.Select(e => e with { Digest = "sha256:" + new string('c', 64) }).ToList(),
        };
        var bytes = JsonSerializer.SerializeToUtf8Bytes(manifest, EngineManifest.JsonOptions);
        return (bytes, ManifestSignature.Sign(bytes, privateKey));
    }

    private sealed class FakeHandler(Func<HttpRequestMessage, string> respond) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(respond(request)) });
    }
}
