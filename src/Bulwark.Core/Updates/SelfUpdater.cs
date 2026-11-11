using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace Bulwark.Core.Updates;

public sealed record SelfUpdateResult(bool Updated, string Message);

/// <summary>
/// Replaces the running Bulwark binary with the release named in the installed (and therefore
/// signature-verified) manifest. The download is checked against the SHA-256 in the manifest,
/// so a compromised download host cannot swap the binary.
/// </summary>
public sealed class SelfUpdater(HttpClient http)
{
    public async Task<SelfUpdateResult> UpdateAsync(
        EngineManifest verifiedManifest, string currentVersion, string executablePath, CancellationToken cancellationToken)
    {
        if (verifiedManifest.Bulwark is not { } release)
        {
            return new(false, "The installed manifest does not list a Bulwark release.");
        }

        if (!IsNewer(release.Version, currentVersion))
        {
            return new(false, $"Bulwark {currentVersion} is current (latest {release.Version}).");
        }

        var rid = RuntimeInformation.RuntimeIdentifier;
        var asset = release.Assets.FirstOrDefault(a => a.Rid.Equals(rid, StringComparison.OrdinalIgnoreCase));
        if (asset is null)
        {
            return new(false, $"Release {release.Version} has no binary for {rid}.");
        }

        if (!asset.Url.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            return new(false, "Refusing to download a release over a non-HTTPS URL.");
        }

        var directory = Path.GetDirectoryName(executablePath)!;
        var download = Path.Combine(directory, $".bulwark-{release.Version}.download");
        try
        {
            await using (var source = await http.GetStreamAsync(asset.Url, cancellationToken))
            await using (var target = File.Create(download))
            {
                await source.CopyToAsync(target, cancellationToken);
            }

            await using (var check = File.OpenRead(download))
            {
                var actual = Convert.ToHexStringLower(await SHA256.HashDataAsync(check, cancellationToken));
                if (!actual.Equals(asset.Sha256, StringComparison.OrdinalIgnoreCase))
                {
                    return new(false, $"Downloaded binary hash {actual[..12]}… does not match the signed manifest. Not installed.");
                }
            }

            if (!OperatingSystem.IsWindows())
            {
                File.SetUnixFileMode(download, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute
                    | UnixFileMode.GroupRead | UnixFileMode.GroupExecute | UnixFileMode.OtherRead | UnixFileMode.OtherExecute);
            }

            // A running executable can be renamed (even on Windows) but not overwritten.
            var old = executablePath + ".old";
            File.Delete(old);
            File.Move(executablePath, old);
            File.Move(download, executablePath);
            TryDelete(old);
            return new(true, $"Updated Bulwark {currentVersion} → {release.Version}.");
        }
        finally
        {
            TryDelete(download);
        }
    }

    public static bool IsNewer(string candidate, string current) =>
        Version.TryParse(candidate.TrimStart('v').Split('-', '+')[0], out var a)
        && Version.TryParse(current.TrimStart('v').Split('-', '+')[0], out var b) && a > b;

    private static void TryDelete(string path)
    {
        try { File.Delete(path); } catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }
    }
}
