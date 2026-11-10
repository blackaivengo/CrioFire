using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using CrioFire.Core.Interop;

namespace CrioFire.Core;

/// <summary>One connection attempt the Windows Filtering Platform dropped.</summary>
/// <param name="FilterId">The filter that dropped it.</param>
/// <param name="Rule">The CrioFire filter responsible, or null when another firewall (e.g. Windows Firewall) dropped it.</param>
public sealed record BlockedConnection(
    DateTime TimeUtc,
    string? AppPath,
    ProtocolType Protocol,
    IPEndPoint? Local,
    IPEndPoint? Remote,
    ulong FilterId,
    CrioFireFilter? Rule)
{
    public bool IsCrioFire => Rule is not null;

    /// <summary>Outbound or inbound when CrioFire's rule tells us; null for other firewalls' drops.</summary>
    public TrafficDirection? Direction => Rule?.Layer?.Direction;

    public string ProtocolName => Protocol switch
    {
        ProtocolType.Tcp => "TCP",
        ProtocolType.Udp => "UDP",
        ProtocolType.Icmp => "ICMP",
        ProtocolType.IcmpV6 => "ICMPv6",
        _ => ((int)Protocol).ToString(System.Globalization.CultureInfo.InvariantCulture),
    };

    /// <summary>One JSON object per line, for the traffic log.</summary>
    public string ToJsonLine()
    {
        using var stream = new MemoryStream();
        using (var w = new Utf8JsonWriter(stream))
        {
            w.WriteStartObject();
            w.WriteString("time", TimeUtc.ToString("O", System.Globalization.CultureInfo.InvariantCulture));
            w.WriteString("app", AppPath);
            w.WriteString("protocol", ProtocolName);
            w.WriteString("local", Local?.ToString());
            w.WriteString("remote", Remote?.ToString());
            w.WriteString("direction", Direction switch
            {
                TrafficDirection.Outbound => "out",
                TrafficDirection.Inbound => "in",
                _ => null,
            });
            w.WriteNumber("filterId", FilterId);
            w.WriteBoolean("criofire", IsCrioFire);
            w.WriteEndObject();
        }

        return Encoding.UTF8.GetString(stream.ToArray());
    }
}

/// <summary>Converts the raw values in WFP net events. Pure logic, unit-tested.</summary>
public static class NetEventDecoding
{
    /// <summary>WFP stores IPv4 addresses as a host-order UINT32 (most significant byte = first octet).</summary>
    public static IPAddress FromHostOrderV4(uint value) =>
        new([(byte)(value >> 24), (byte)(value >> 16), (byte)(value >> 8), (byte)value]);

    /// <summary>Decodes a WFP app ID blob: a NUL-terminated UTF-16 NT path such as \device\harddiskvolume3\app.exe.</summary>
    public static string? DecodeAppId(ReadOnlySpan<byte> blob)
    {
        if (blob.Length < 2)
        {
            return null;
        }

        var text = Encoding.Unicode.GetString(blob);
        var nul = text.IndexOf('\0', StringComparison.Ordinal);
        return nul >= 0 ? text[..nul] : text;
    }
}

/// <summary>
/// Maps NT device paths (\device\harddiskvolume3\x) back to drive-letter paths (C:\x).
/// </summary>
public sealed class NtPathMapper
{
    private readonly IReadOnlyList<(string Device, string Drive)> _devices;

    /// <param name="devices">Pairs like ("\Device\HarddiskVolume3", "C:").</param>
    public NtPathMapper(IEnumerable<(string Device, string Drive)> devices)
    {
        // Longest device names first, so \Device\HarddiskVolume10 is not matched as \Device\HarddiskVolume1.
        _devices = devices.OrderByDescending(d => d.Device.Length).ToArray();
    }

    /// <summary>Reads the current drive letter mappings from Windows.</summary>
    public static unsafe NtPathMapper FromSystem()
    {
        var pairs = new List<(string, string)>();
        var buffer = stackalloc char[1024];
        for (var letter = 'A'; letter <= 'Z'; letter++)
        {
            var drive = $"{letter}:";
            var length = Kernel32.QueryDosDevice(drive, buffer, 1024);
            if (length > 0)
            {
                pairs.Add((new string(buffer), drive));   // first NUL-terminated entry
            }
        }

        return new NtPathMapper(pairs);
    }

    public string ToDosPath(string ntPath)
    {
        ArgumentNullException.ThrowIfNull(ntPath);
        foreach (var (device, drive) in _devices)
        {
            if (ntPath.StartsWith(device, StringComparison.OrdinalIgnoreCase)
                && (ntPath.Length == device.Length || ntPath[device.Length] == '\\'))
            {
                return drive + ntPath[device.Length..];
            }
        }

        return ntPath;   // e.g. "System" or a path on a device without a drive letter
    }
}
