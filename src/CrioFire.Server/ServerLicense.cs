using System.Security.Cryptography;
using CrioFire.Core;

namespace CrioFire.Server;

/// <summary>The license as the console shows it, with its seats counted against the enrolled PCs.</summary>
/// <param name="Over">More PCs are enrolled than the license covers.</param>
public sealed record LicenseView(
    string State,
    string Message,
    string? Licensee,
    string? Edition,
    int Seats,
    int Computers,
    bool Over,
    DateTime? ExpiresUtc,
    string? LicenseId);

/// <summary>
/// The organization's CrioFire license, kept on the server (license.key in the data folder). The
/// server gives it to every PC that reports to it, so nobody types the key on each PC. Seats are
/// counted, not enforced: going over is shown to administrators, and protection never stops.
/// </summary>
public sealed class ServerLicense(string folder, ECDsa? publicKey)
{
    private readonly object _gate = new();

    public string FilePath { get; } = Path.Combine(folder, "license.key");

    public string? Key
    {
        get
        {
            lock (_gate)
            {
                return File.Exists(FilePath) ? File.ReadAllText(FilePath).Trim() : null;
            }
        }
    }

    /// <remarks>Checks run one at a time: the public key object is shared by every check-in.</remarks>
    public LicenseStatus Status(DateTime nowUtc)
    {
        lock (_gate)
        {
            return LicenseKeys.Check(Key, nowUtc, publicKey);
        }
    }

    /// <summary>Uses a key, after checking it is CrioSoft's and still valid. Null removes the key.</summary>
    public LicenseStatus Set(string? key, DateTime nowUtc)
    {
        lock (_gate)
        {
            if (string.IsNullOrWhiteSpace(key))
            {
                if (File.Exists(FilePath))
                {
                    File.Delete(FilePath);
                }

                return LicenseKeys.Check(null, nowUtc, publicKey);
            }

            var status = LicenseKeys.Check(key, nowUtc, publicKey);
            if (!status.IsLicensed)
            {
                throw new ArgumentException(status.State == LicenseStates.Expired
                    ? $"This license has expired. {status.Message}"
                    : status.Message);
            }

            Directory.CreateDirectory(Path.GetDirectoryName(FilePath)!);
            File.WriteAllText(FilePath + ".tmp", LicenseKeys.Clean(key));
            File.Move(FilePath + ".tmp", FilePath, overwrite: true);
            return status;
        }
    }

    /// <summary>
    /// The key to give a PC at check-in: only a valid license, and only when the PC does not have it
    /// yet, so most check-in answers stay a few bytes.
    /// </summary>
    public string? KeyFor(string? pcLicenseId, DateTime nowUtc)
    {
        string? key;
        LicenseStatus status;
        lock (_gate)
        {
            key = Key;
            status = LicenseKeys.Check(key, nowUtc, publicKey);
        }

        return status.IsLicensed && !string.Equals(pcLicenseId, status.LicenseId, StringComparison.Ordinal) ? LicenseKeys.Clean(key) : null;
    }

    public LicenseView View(int computers, DateTime nowUtc)
    {
        var s = Status(nowUtc);
        var counted = s.Seats > 0 && s.State is not (LicenseStates.None or LicenseStates.Invalid or LicenseStates.Unavailable);
        return new LicenseView(s.State, s.Message, s.Licensee, s.Edition, s.Seats, computers, counted && computers > s.Seats, s.ExpiresUtc, s.LicenseId);
    }

    /// <summary>One line for the command line and the overview.</summary>
    public static string Describe(LicenseView v) => v.State switch
    {
        LicenseStates.None => $"No license on this server. {v.Computers} computer(s) enrolled. Free use covers businesses with up to 3 computers.",
        LicenseStates.Invalid or LicenseStates.Unavailable => v.Message,
        _ => $"{v.Message} Seats: {v.Computers} of {v.Seats} used." + (v.Over ? $" {v.Computers - v.Seats} more than the license covers." : string.Empty),
    };
}
