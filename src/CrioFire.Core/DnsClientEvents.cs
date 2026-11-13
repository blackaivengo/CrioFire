using System.Net;
using System.Runtime.InteropServices;

namespace CrioFire.Core;

/// <summary>
/// Follows Windows' own name lookups as they complete, through a real-time event tracing session on
/// the Microsoft-Windows-DNS-Client provider (event 3008, "DNS query is completed"). Nothing is
/// written to disk: each lookup goes to <see cref="Lookup"/> and is gone. Needs administrator or
/// SYSTEM rights. Lookups an application makes itself (a browser's own encrypted DNS) are not seen.
/// </summary>
public sealed class DnsClientEvents : IDisposable
{
    public const string SessionName = "CrioFire-DNS";

    private static readonly Guid DnsClientProvider = new("1c95126e-7eea-49a9-a3fe-a378b03ddb4d");
    private const ushort QueryCompleted = 3008;

    private readonly RealTimeTrace _trace;

    public DnsClientEvents() => _trace = new RealTimeTrace(SessionName, "CrioFire DNS lookups", DnsClientProvider, OnEvent);

    /// <summary>Raised on the tracing thread for each completed lookup that returned addresses.</summary>
    public event Action<DnsLookup>? Lookup;

    /// <summary>Starts the session and its reading thread. Throws <see cref="IOException"/> if Windows refuses.</summary>
    public void Start() => _trace.Start();

    public void Dispose() => _trace.Dispose();

    private void OnEvent(ushort id, ReadOnlySpan<byte> data)
    {
        if (id == QueryCompleted && ParseQueryCompleted(data) is { } lookup)
        {
            Lookup?.Invoke(lookup);
        }
    }

    /// <summary>
    /// Parses QueryResults as the DNS client writes it: "type:  5 cdn.example.net;::ffff:93.184.216.34;2606:2800::1;"
    /// (CNAME names after "type:  5", IPv4 addresses often as IPv4-mapped IPv6).
    /// </summary>
    public static (List<string> Aliases, List<IPAddress> Addresses) ParseResults(string? results)
    {
        var aliases = new List<string>();
        var addresses = new List<IPAddress>();
        foreach (var part in (results ?? string.Empty).Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (part.StartsWith("type:", StringComparison.OrdinalIgnoreCase))
            {
                var fields = part[5..].Split(' ', StringSplitOptions.RemoveEmptyEntries);
                if (fields.Length >= 2 && fields[0] == "5")
                {
                    aliases.Add(fields[1].TrimEnd('.').ToLowerInvariant());
                }
            }
            else if (IPAddress.TryParse(part, out var address))
            {
                addresses.Add(address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address);
            }
        }

        return (aliases, addresses);
    }

    /// <summary>
    /// Reads event 3008's data: QueryName (UTF-16, null-terminated), QueryType (UInt32),
    /// QueryOptions (UInt64), QueryStatus (UInt32), QueryResults (UTF-16, null-terminated).
    /// Null for anything that does not fit that shape, or a lookup that failed.
    /// </summary>
    public static DnsLookup? ParseQueryCompleted(ReadOnlySpan<byte> data)
    {
        if (!TryReadString(ref data, out var name) || data.Length < 16)
        {
            return null;
        }

        var status = MemoryMarshal.Read<uint>(data[12..]);
        data = data[16..];
        if (status != 0 || name.Length == 0 || !TryReadString(ref data, out var results))
        {
            return null;
        }

        var (aliases, addresses) = ParseResults(results);
        return addresses.Count == 0 ? null : new DnsLookup(name.TrimEnd('.').ToLowerInvariant(), aliases, addresses);
    }

    private static bool TryReadString(ref ReadOnlySpan<byte> data, out string text)
    {
        var chars = MemoryMarshal.Cast<byte, char>(data[..(data.Length & ~1)]);
        var end = chars.IndexOf('\0');
        if (end < 0)
        {
            text = string.Empty;
            return false;
        }

        text = new string(chars[..end]);
        data = data[((end + 1) * 2)..];
        return true;
    }
}
