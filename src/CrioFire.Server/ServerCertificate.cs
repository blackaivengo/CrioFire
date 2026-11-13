using System.Net.NetworkInformation;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace CrioFire.Server;

/// <summary>
/// The server's HTTPS certificate. By default the server makes its own (self-signed, valid 10
/// years) on first start, and PCs pin its fingerprint when they enroll, so no certificate
/// authority is needed. A company certificate can be used instead (settings.json).
/// </summary>
public static class ServerCertificate
{
    public const string FileName = "server-certificate.pfx";

    public static X509Certificate2 LoadOrCreate(string folder, DateTime nowUtc)
    {
        var path = Path.Combine(folder, FileName);
        if (File.Exists(path))
        {
            return X509CertificateLoader.LoadPkcs12FromFile(path, password: null);
        }

        Directory.CreateDirectory(folder);
        File.WriteAllBytes(path, CreateSelfSigned(HostNames(), nowUtc));
        return X509CertificateLoader.LoadPkcs12FromFile(path, password: null);
    }

    /// <summary>A self-signed server certificate (ECDSA P-256) for the given names, as PFX bytes without a password.</summary>
    public static byte[] CreateSelfSigned(IReadOnlyList<string> names, DateTime nowUtc)
    {
        ArgumentNullException.ThrowIfNull(names);
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest($"CN={names[0]}, O=CrioFire Server", key, HashAlgorithmName.SHA256);
        var san = new SubjectAlternativeNameBuilder();
        foreach (var name in names.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            san.AddDnsName(name);
        }

        request.CertificateExtensions.Add(san.Build());
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.1")], false));
        using var certificate = request.CreateSelfSigned(nowUtc.AddDays(-1), nowUtc.AddYears(10));
        return certificate.Export(X509ContentType.Pfx);
    }

    /// <summary>This machine's names: its name, its full domain name when it has one, and localhost.</summary>
    public static IReadOnlyList<string> HostNames()
    {
        var names = new List<string> { Environment.MachineName.ToLowerInvariant() };
        var domain = IPGlobalProperties.GetIPGlobalProperties().DomainName;
        if (!string.IsNullOrEmpty(domain))
        {
            names.Add($"{names[0]}.{domain}".ToLowerInvariant());
        }

        names.Add("localhost");
        return names;
    }
}
