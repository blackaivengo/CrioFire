using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace CrioFire.Core;

/// <summary>
/// What a business license key says. Signed by CrioSoft; CrioFire checks the signature itself with
/// the public key built into it, so no activation server is needed.
/// </summary>
/// <param name="Edition">business, provider (an IT service provider) or trial.</param>
/// <param name="Seats">How many computers the license covers.</param>
public sealed record LicenseData(
    int Format,
    string LicenseId,
    string Licensee,
    string? Email,
    string Edition,
    int Seats,
    DateTime IssuedUtc,
    DateTime ExpiresUtc);

/// <summary>How a license key checks out, for the app, the command line and later the admin server.</summary>
/// <param name="State">none (free use), valid, expiring (valid, less than 30 days left), expired, invalid or unavailable (no public key in this build).</param>
public sealed record LicenseStatus(string State, string Message, string? Licensee = null, string? Edition = null, int Seats = 0, DateTime? ExpiresUtc = null, string? LicenseId = null)
{
    public bool IsLicensed => State is LicenseStates.Valid or LicenseStates.Expiring;
}

public static class LicenseStates
{
    public const string None = "none";
    public const string Valid = "valid";
    public const string Expiring = "expiring";
    public const string Expired = "expired";
    public const string Invalid = "invalid";
    public const string Unavailable = "unavailable";
}

/// <summary>
/// License keys: <c>CRIOFIRE1.&lt;payload&gt;.&lt;signature&gt;</c>, both base64url. The payload is
/// the JSON of <see cref="LicenseData"/>; the signature is ECDSA P-256 with SHA-256 over the payload
/// bytes. Expired licenses never switch protection off: CrioFire keeps working and says so.
/// </summary>
public static class LicenseKeys
{
    public const string Prefix = "CRIOFIRE1";
    public const int CurrentFormat = 1;
    public static readonly string[] Editions = ["business", "provider", "trial"];
    private static readonly TimeSpan ExpiringSoon = TimeSpan.FromDays(30);

    /// <summary>Signs a license. Used by CrioSoft's license tool, with the private key that never leaves CrioSoft.</summary>
    public static string Issue(LicenseData data, ECDsa privateKey)
    {
        ArgumentNullException.ThrowIfNull(data);
        ArgumentNullException.ThrowIfNull(privateKey);
        var payload = JsonSerializer.SerializeToUtf8Bytes(data, LicenseJson.Default.LicenseData);
        var signature = privateKey.SignData(payload, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        return $"{Prefix}.{Base64Url(payload)}.{Base64Url(signature)}";
    }

    /// <summary>The license in a key when its signature is CrioSoft's; otherwise null and why.</summary>
    public static LicenseData? Read(string? key, ECDsa publicKey, out string? error)
    {
        ArgumentNullException.ThrowIfNull(publicKey);
        error = null;
        var parts = Clean(key).Split('.');
        if (parts.Length != 3 || parts[0] != Prefix)
        {
            error = "This is not a CrioFire license key.";
            return null;
        }

        byte[] payload, signature;
        try
        {
            payload = FromBase64Url(parts[1]);
            signature = FromBase64Url(parts[2]);
        }
        catch (FormatException)
        {
            error = "The license key is damaged. Copy it again from the email you received.";
            return null;
        }

        if (!publicKey.VerifyData(payload, signature, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
        {
            error = "The license key is not valid: it was not issued by CrioSoft, or it was changed.";
            return null;
        }

        try
        {
            var data = JsonSerializer.Deserialize(payload, LicenseJson.Default.LicenseData);
            if (data is null || data.Format > CurrentFormat)
            {
                error = "This license key needs a newer version of CrioFire.";
                return null;
            }

            return data;
        }
        catch (JsonException)
        {
            error = "The license key is damaged.";
            return null;
        }
    }

    /// <summary>Checks a key (or none) at a moment in time.</summary>
    public static LicenseStatus Check(string? key, DateTime nowUtc, ECDsa? publicKey)
    {
        if (string.IsNullOrWhiteSpace(key))
        {
            return new LicenseStatus(LicenseStates.None,
                "Free use: personal use, non-profits, schools, government, and businesses with up to 3 computers.");
        }

        if (publicKey is null)
        {
            return new LicenseStatus(LicenseStates.Unavailable, "This build of CrioFire cannot check license keys.");
        }

        if (Read(key, publicKey, out var error) is not { } data)
        {
            return new LicenseStatus(LicenseStates.Invalid, error!);
        }

        var seats = data.Seats == 1 ? "1 computer" : $"{data.Seats} computers";
        var edition = data.Edition switch { "provider" => "Service provider license", "trial" => "Business trial", _ => "Business license" };
        if (nowUtc >= data.ExpiresUtc)
        {
            return new LicenseStatus(LicenseStates.Expired,
                $"{edition} for {data.Licensee} ({seats}) expired on {data.ExpiresUtc:d}. CrioFire keeps protecting this PC; renew to stay covered.",
                data.Licensee, data.Edition, data.Seats, data.ExpiresUtc, data.LicenseId);
        }

        var state = data.ExpiresUtc - nowUtc < ExpiringSoon ? LicenseStates.Expiring : LicenseStates.Valid;
        var until = state == LicenseStates.Expiring ? $"; expires {data.ExpiresUtc:d}, renew soon" : $", until {data.ExpiresUtc:d}";
        return new LicenseStatus(state, $"{edition} for {data.Licensee}: {seats}{until}.",
            data.Licensee, data.Edition, data.Seats, data.ExpiresUtc, data.LicenseId);
    }

    /// <summary>
    /// CrioSoft's public key, built into CrioFire (LicensePublicKey.pem). Null when this build has
    /// none (a self-built copy, or before CrioSoft has created its key pair).
    /// </summary>
    public static ECDsa? ProductPublicKey()
    {
        using var stream = typeof(LicenseKeys).Assembly.GetManifestResourceStream("CrioFire.Core.LicensePublicKey.pem");
        if (stream is null)
        {
            return null;
        }

        using var reader = new StreamReader(stream, Encoding.UTF8);
        var pem = reader.ReadToEnd();
        if (!pem.Contains("-----BEGIN PUBLIC KEY-----", StringComparison.Ordinal))
        {
            return null;
        }

        var key = ECDsa.Create();
        try
        {
            key.ImportFromPem(pem);
            return key;
        }
        catch (Exception ex) when (ex is ArgumentException or CryptographicException)
        {
            key.Dispose();
            return null;
        }
    }

    /// <summary>Removes spaces and line breaks a key picks up when copied from an email.</summary>
    public static string Clean(string? key) =>
        new((key ?? string.Empty).Where(c => !char.IsWhiteSpace(c)).ToArray());

    private static string Base64Url(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static byte[] FromBase64Url(string text)
    {
        var s = text.Replace('-', '+').Replace('_', '/');
        return Convert.FromBase64String(s.PadRight(s.Length + ((4 - (s.Length % 4)) % 4), '='));
    }
}

/// <summary>The license key entered on this PC: %ProgramData%\criofire\license.key.</summary>
public sealed class LicenseStore(string path)
{
    public static string DefaultPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "criofire", "license.key");

    public string FilePath { get; } = path;

    public string? Key => File.Exists(FilePath) ? File.ReadAllText(FilePath).Trim() : null;

    public void Set(string? key)
    {
        if (string.IsNullOrWhiteSpace(key))
        {
            File.Delete(FilePath);
            return;
        }

        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(FilePath))!);
        File.WriteAllText(FilePath, LicenseKeys.Clean(key));
    }
}

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(LicenseData))]
internal sealed partial class LicenseJson : JsonSerializerContext
{
}
