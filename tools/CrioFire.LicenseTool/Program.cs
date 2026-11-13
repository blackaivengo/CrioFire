using System.Globalization;
using System.Security.Cryptography;
using CrioFire.Core;

// criofire-license: CrioSoft's tool for license keys. The private key stays on CrioSoft's own
// computer (ideally offline media), encrypted with a password; only the public key goes into the
// CrioFire source code.

const string PrivateFile = "criofire-license-private.pem";
const string PublicFile = "LicensePublicKey.pem";
const string LogFile = "issued-licenses.csv";

try
{
    return args.Length == 0 ? Usage() : args[0].ToLowerInvariant() switch
    {
        "newkey" when args.Length == 2 => NewKey(args[1]),
        "issue" => Issue(args[1..]),
        "verify" when args.Length is 2 or 4 => Verify(args[1], args.Length == 4 && args[2] == "--public" ? args[3] : null),
        _ => Usage(),
    };
}
catch (Exception ex) when (ex is IOException or CryptographicException or ArgumentException or UnauthorizedAccessException)
{
    Console.Error.WriteLine(ex.Message);
    return 1;
}

static int Usage()
{
    Console.WriteLine("""
        criofire-license: create CrioSoft's signing key and issue CrioFire license keys

          criofire-license newkey <folder>
              Creates the key pair in <folder> (keep it outside the repository, ideally offline):
              criofire-license-private.pem (encrypted with a password you choose) and
              LicensePublicKey.pem (copy it to src/CrioFire.Core/LicensePublicKey.pem).

          criofire-license issue --key <private.pem> --to "<company>" --seats <n>
                                 [--email <address>] [--edition business|provider|trial]
                                 [--months <n> | --days <n>]
              Prints a license key (default: business, 12 months; trial: 30 days) and records it in
              issued-licenses.csv next to the private key.

          criofire-license verify <key> [--public <LicensePublicKey.pem>]
              Shows what a key contains and whether it checks out (default: the key built in).
        """);
    return 2;
}

static int NewKey(string folder)
{
    Directory.CreateDirectory(folder);
    var privatePath = Path.Combine(folder, PrivateFile);
    if (File.Exists(privatePath))
    {
        throw new IOException($"{privatePath} exists already. Keys are not replaced: every license issued with it would stop working.");
    }

    var password = Password("Password for the private key: ");
    if (password != Password("Same password again: "))
    {
        throw new ArgumentException("The passwords differ.");
    }

    if (password.Length < 12)
    {
        throw new ArgumentException("Use at least 12 characters.");
    }

    using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    var pbe = new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 600_000);
    File.WriteAllText(privatePath, key.ExportEncryptedPkcs8PrivateKeyPem(password, pbe));
    File.WriteAllText(Path.Combine(folder, PublicFile), key.ExportSubjectPublicKeyInfoPem() + Environment.NewLine);
    Console.WriteLine($"""
        Created {privatePath}
        Created {Path.Combine(folder, PublicFile)}

        Next: copy {PublicFile} over src/CrioFire.Core/{PublicFile}, commit it, and keep the private
        key and its password safe. If the private key is lost, no new licenses can be issued for
        existing CrioFire versions; if it leaks, anyone can make keys.
        """);
    return 0;
}

static int Issue(string[] args)
{
    string? keyPath = null, licensee = null, email = null, edition = "business";
    int seats = 0;
    int? months = null, days = null;
    for (var i = 0; i < args.Length; i++)
    {
        var value = i + 1 < args.Length ? args[i + 1] : throw new ArgumentException($"{args[i]} needs a value.");
        switch (args[i])
        {
            case "--key": keyPath = value; break;
            case "--to": licensee = value; break;
            case "--email": email = value; break;
            case "--edition": edition = value.ToLowerInvariant(); break;
            case "--seats": seats = int.Parse(value, CultureInfo.InvariantCulture); break;
            case "--months": months = int.Parse(value, CultureInfo.InvariantCulture); break;
            case "--days": days = int.Parse(value, CultureInfo.InvariantCulture); break;
            default: throw new ArgumentException($"Unknown option {args[i]}.");
        }

        i++;
    }

    if (keyPath is null || string.IsNullOrWhiteSpace(licensee) || seats < 1 || !LicenseKeys.Editions.Contains(edition))
    {
        Usage();
        return 2;
    }

    using var key = ECDsa.Create();
    key.ImportFromEncryptedPem(File.ReadAllText(keyPath), Password("Password for the private key: "));
    var now = DateTime.UtcNow;
    var expires = days is int d ? now.AddDays(d)
        : months is int m ? now.AddMonths(m)
        : edition == "trial" ? now.AddDays(30) : now.AddMonths(12);
    var data = new LicenseData(
        LicenseKeys.CurrentFormat,
        $"CF-{now:yyyyMMdd}-{Convert.ToHexString(RandomNumberGenerator.GetBytes(3))}",
        licensee.Trim(),
        email,
        edition,
        seats,
        now,
        expires.Date);
    var licenseKey = LicenseKeys.Issue(data, key);

    var log = Path.Combine(Path.GetDirectoryName(Path.GetFullPath(keyPath))!, LogFile);
    if (!File.Exists(log))
    {
        File.WriteAllText(log, "licenseId,licensee,email,edition,seats,issuedUtc,expiresUtc" + Environment.NewLine);
    }

    File.AppendAllText(log, string.Join(',', data.LicenseId, Csv(data.Licensee), Csv(data.Email ?? string.Empty), data.Edition,
        data.Seats.ToString(CultureInfo.InvariantCulture), data.IssuedUtc.ToString("O", CultureInfo.InvariantCulture),
        data.ExpiresUtc.ToString("O", CultureInfo.InvariantCulture)) + Environment.NewLine);

    Console.WriteLine($"License {data.LicenseId} for {data.Licensee}: {data.Seats} computer(s), {data.Edition}, until {data.ExpiresUtc:yyyy-MM-dd}.");
    Console.WriteLine();
    Console.WriteLine(licenseKey);
    return 0;
}

static int Verify(string licenseKey, string? publicPath)
{
    ECDsa? key;
    if (publicPath is null)
    {
        key = LicenseKeys.ProductPublicKey();
    }
    else
    {
        key = ECDsa.Create();
        key.ImportFromPem(File.ReadAllText(publicPath));
    }

    using (key)
    {
        var status = LicenseKeys.Check(licenseKey, DateTime.UtcNow, key);
        Console.WriteLine($"{status.State}: {status.Message}");
        if (status.LicenseId is { } id)
        {
            Console.WriteLine($"License ID: {id}");
        }

        return status.IsLicensed ? 0 : 1;
    }
}

static string Csv(string text) => text.Contains(',') || text.Contains('"') ? "\"" + text.Replace("\"", "\"\"") + "\"" : text;

static string Password(string prompt)
{
    Console.Write(prompt);
    if (Console.IsInputRedirected)
    {
        var line = Console.ReadLine() ?? string.Empty;   // scripted use: the password on standard input
        Console.WriteLine();
        return line;
    }

    var chars = new List<char>();
    while (true)
    {
        var k = Console.ReadKey(intercept: true);
        if (k.Key == ConsoleKey.Enter)
        {
            break;
        }

        if (k.Key == ConsoleKey.Backspace)
        {
            if (chars.Count > 0)
            {
                chars.RemoveAt(chars.Count - 1);
            }

            continue;
        }

        chars.Add(k.KeyChar);
    }

    Console.WriteLine();
    return new string(chars.ToArray());
}
