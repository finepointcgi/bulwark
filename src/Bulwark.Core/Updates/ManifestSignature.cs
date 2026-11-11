using System.Security.Cryptography;

namespace Bulwark.Core.Updates;

/// <summary>
/// ECDSA P-256 / SHA-256 signatures over the raw manifest bytes. The format matches
/// <c>cosign sign-blob --key</c> (base64 DER signature), so releases can be signed with
/// standard tooling and verified here without shelling out to cosign.
/// </summary>
public static class ManifestSignature
{
    public static bool Verify(ReadOnlySpan<byte> manifest, string base64Signature, string publicKeyPem)
    {
        byte[] signature;
        try
        {
            signature = Convert.FromBase64String(base64Signature.Trim());
        }
        catch (FormatException)
        {
            return false;
        }

        using var key = ECDsa.Create();
        key.ImportFromPem(publicKeyPem);
        return key.VerifyData(manifest, signature, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
    }

    public static string Sign(ReadOnlySpan<byte> manifest, string privateKeyPem)
    {
        using var key = ECDsa.Create();
        key.ImportFromPem(privateKeyPem);
        var signature = key.SignData(manifest, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
        return Convert.ToBase64String(signature);
    }

    /// <summary>Creates a new signing key pair for maintainers. Keep the private key out of the repo.</summary>
    public static (string PrivateKeyPem, string PublicKeyPem) CreateKeyPair()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        return (key.ExportPkcs8PrivateKeyPem(), key.ExportSubjectPublicKeyInfoPem());
    }
}
