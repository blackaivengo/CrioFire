using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Numerics;

namespace CrioFire.Core;

/// <summary>Which transport protocol a network rule covers.</summary>
public enum NetProtocol
{
    Any,
    Tcp,
    Udp,
}

/// <summary>A port or an inclusive range of ports, e.g. 445 or 8000-8100.</summary>
public readonly record struct PortRange(ushort Low, ushort High)
{
    public override string ToString() => Low == High
        ? Low.ToString(CultureInfo.InvariantCulture)
        : string.Create(CultureInfo.InvariantCulture, $"{Low}-{High}");

    /// <summary>Parses "80", "8000-8100" or a comma-separated list of those. Empty or "*" = no ports.</summary>
    public static bool TryParseList(string? text, out List<PortRange> ports, out string? error)
    {
        ports = [];
        error = null;
        if (string.IsNullOrWhiteSpace(text) || text.Trim() == "*")
        {
            return true;
        }

        foreach (var raw in text.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var dash = raw.IndexOf('-', StringComparison.Ordinal);
            var lowText = dash < 0 ? raw : raw[..dash].Trim();
            var highText = dash < 0 ? raw : raw[(dash + 1)..].Trim();
            if (!ushort.TryParse(lowText, NumberStyles.None, CultureInfo.InvariantCulture, out var low)
                || !ushort.TryParse(highText, NumberStyles.None, CultureInfo.InvariantCulture, out var high)
                || low == 0 || high < low)
            {
                error = $"'{raw}' is not a port (1-65535) or a range like 8000-8100.";
                return false;
            }

            ports.Add(new PortRange(low, high));
        }

        return true;
    }
}

/// <summary>A remote address, CIDR block (10.0.0.0/8, 2001:db8::/32) or inclusive range (a-b).</summary>
public sealed record AddressRange(IPAddress Low, IPAddress High, string Text)
{
    public AddressFamily Family => Low.AddressFamily;

    public override string ToString() => Text;

    public bool Contains(IPAddress address)
    {
        ArgumentNullException.ThrowIfNull(address);
        if (address.IsIPv4MappedToIPv6)
        {
            address = address.MapToIPv4();
        }

        if (address.AddressFamily != Family)
        {
            return false;
        }

        var value = ToNumber(address);
        return value >= ToNumber(Low) && value <= ToNumber(High);
    }

    public static bool TryParse(string? text, out AddressRange? range)
    {
        range = null;
        var t = text?.Trim();
        if (string.IsNullOrEmpty(t))
        {
            return false;
        }

        var slash = t.IndexOf('/', StringComparison.Ordinal);
        if (slash > 0)
        {
            if (!TryParseIp(t[..slash], out var network)
                || !int.TryParse(t[(slash + 1)..], NumberStyles.None, CultureInfo.InvariantCulture, out var prefix))
            {
                return false;
            }

            var bits = network.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
            if (prefix < 0 || prefix > bits)
            {
                return false;
            }

            var hostBits = bits - prefix;
            var all = (BigInteger.One << bits) - 1;
            var hostMask = (BigInteger.One << hostBits) - 1;
            var low = ToNumber(network) & (all ^ hostMask);
            var high = low | hostMask;
            range = new AddressRange(FromNumber(low, network.AddressFamily), FromNumber(high, network.AddressFamily), t);
            return true;
        }

        var dash = t.IndexOf('-', StringComparison.Ordinal);
        if (dash > 0)
        {
            if (!TryParseIp(t[..dash].Trim(), out var a) || !TryParseIp(t[(dash + 1)..].Trim(), out var b)
                || a.AddressFamily != b.AddressFamily || ToNumber(b) < ToNumber(a))
            {
                return false;
            }

            range = new AddressRange(a, b, t);
            return true;
        }

        if (!TryParseIp(t, out var single))
        {
            return false;
        }

        range = new AddressRange(single, single, t);
        return true;
    }

    /// <summary>Parses a comma-separated list. Empty or "*" = any address.</summary>
    public static bool TryParseList(string? text, out List<AddressRange> ranges, out string? error)
    {
        ranges = [];
        error = null;
        if (string.IsNullOrWhiteSpace(text) || text.Trim() == "*")
        {
            return true;
        }

        foreach (var raw in text.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (!TryParse(raw, out var range))
            {
                error = $"'{raw}' is not an IP address, a block like 10.0.0.0/8, or a range like 10.0.0.1-10.0.0.50.";
                return false;
            }

            ranges.Add(range!);
        }

        return true;
    }

    /// <summary>Strict: IPv4 needs all four parts ("10.0.0" is not 10.0.0.0); no host names.</summary>
    private static bool TryParseIp(string text, [System.Diagnostics.CodeAnalysis.NotNullWhen(true)] out IPAddress? address)
    {
        if (!IPAddress.TryParse(text, out address))
        {
            return false;
        }

        return address.AddressFamily switch
        {
            AddressFamily.InterNetwork => text.Count(c => c == '.') == 3,
            AddressFamily.InterNetworkV6 => text.Contains(':', StringComparison.Ordinal),
            _ => false,
        };
    }

    internal static BigInteger ToNumber(IPAddress address) => new(address.GetAddressBytes(), isUnsigned: true, isBigEndian: true);

    private static IPAddress FromNumber(BigInteger value, AddressFamily family)
    {
        var length = family == AddressFamily.InterNetwork ? 4 : 16;
        var bytes = value.ToByteArray(isUnsigned: true, isBigEndian: true);
        var padded = new byte[length];
        Array.Copy(bytes, 0, padded, length - bytes.Length, bytes.Length);
        return new IPAddress(padded);
    }
}

/// <summary>
/// A rule by port and/or remote address, optionally for one program: e.g. "block TCP 445
/// inbound", "allow C:\app.exe on remote port 443 only", "block 203.0.113.0/24".
/// Ports are the remote port for outbound connections and the local port for inbound ones.
/// Stored in the filter description, like app rules:
/// <c>criofire:v1|net|block|in|tcp|445|*|*</c> (action, direction, protocol, ports, addresses, program).
/// </summary>
public sealed record NetRule(RuleAction Action, TrafficDirection Direction, NetProtocol Protocol, string Ports, string Addresses, string? AppPath)
{
    public const string Tag = "net";

    /// <summary>Validates and normalizes; returns null and an error for rules that make no sense.</summary>
    public static NetRule? Create(RuleAction action, TrafficDirection direction, NetProtocol protocol, string? ports, string? addresses, string? appPath, out string? error)
    {
        if (!PortRange.TryParseList(ports, out var portList, out error) || !AddressRange.TryParseList(addresses, out var addressList, out error))
        {
            return null;
        }

        if (portList.Count == 0 && addressList.Count == 0 && protocol == NetProtocol.Any)
        {
            error = "Give at least a port, an address or a protocol. To allow or block a whole program, use a program rule.";
            return null;
        }

        if (direction == 0 || (direction & ~TrafficDirection.Both) != 0)
        {
            error = "Direction must be out, in or both.";
            return null;
        }

        var app = string.IsNullOrWhiteSpace(appPath) ? null : Path.GetFullPath(appPath);
        return new NetRule(action, direction, protocol, string.Join(',', portList), string.Join(',', addressList), app);
    }

    public IReadOnlyList<PortRange> PortList => PortRange.TryParseList(Ports, out var list, out _) ? list : [];

    public IReadOnlyList<AddressRange> AddressList => AddressRange.TryParseList(Addresses, out var list, out _) ? list : [];

    /// <summary>More specific rules win: program + port/address beats port/address beats a plain program rule; block beats allow.</summary>
    public byte Weight => (byte)((AppPath is null ? 12 : 14) + (Action == RuleAction.Block ? 1 : 0));

    public string Format() => string.Join('|',
        RuleDescription.Prefix, Tag, RuleDescription.ActionText(Action), RuleDescription.DirectionText(Direction),
        ProtocolText(Protocol), Ports.Length == 0 ? "*" : Ports, Addresses.Length == 0 ? "*" : Addresses, AppPath ?? "*");

    /// <summary>A short human description, e.g. "TCP 445 in" or "203.0.113.0/24 · Chat.exe".</summary>
    public string Summary()
    {
        var parts = new List<string>();
        if (Protocol != NetProtocol.Any)
        {
            parts.Add(Protocol.ToString().ToUpperInvariant());
        }

        if (Ports.Length > 0)
        {
            parts.Add((Direction == TrafficDirection.Inbound ? "local port " : "port ") + Ports);
        }

        if (Addresses.Length > 0)
        {
            parts.Add(Addresses);
        }

        if (AppPath is not null)
        {
            parts.Add(AppPath[(AppPath.LastIndexOfAny(['\\', '/']) + 1)..]);
        }

        return string.Join(" · ", parts);
    }

    public static bool TryParse(string? text, out NetRule? rule)
    {
        rule = null;
        var parts = text?.Split('|', 8);
        if (parts is not { Length: 8 } || parts[0] != RuleDescription.Prefix || parts[1] != Tag)
        {
            return false;
        }

        RuleAction? action = parts[2] switch { "block" => RuleAction.Block, "allow" => RuleAction.Allow, _ => null };
        TrafficDirection? direction = parts[3] switch
        {
            "out" => TrafficDirection.Outbound,
            "in" => TrafficDirection.Inbound,
            "both" => TrafficDirection.Both,
            _ => null,
        };
        NetProtocol? protocol = parts[4] switch { "any" => NetProtocol.Any, "tcp" => NetProtocol.Tcp, "udp" => NetProtocol.Udp, _ => null };
        if (action is null || direction is null || protocol is null)
        {
            return false;
        }

        var ports = parts[5] == "*" ? string.Empty : parts[5];
        var addresses = parts[6] == "*" ? string.Empty : parts[6];
        if (!PortRange.TryParseList(ports, out _, out _) || !AddressRange.TryParseList(addresses, out _, out _))
        {
            return false;
        }

        rule = new NetRule(action.Value, direction.Value, protocol.Value, ports, addresses, parts[7] == "*" ? null : parts[7]);
        return true;
    }

    public static string ProtocolText(NetProtocol protocol) => protocol switch
    {
        NetProtocol.Tcp => "tcp",
        NetProtocol.Udp => "udp",
        _ => "any",
    };

    public static bool TryParseProtocol(string? text, out NetProtocol protocol)
    {
        switch (text?.Trim().ToLowerInvariant())
        {
            case null or "" or "any":
                protocol = NetProtocol.Any;
                return true;
            case "tcp":
                protocol = NetProtocol.Tcp;
                return true;
            case "udp":
                protocol = NetProtocol.Udp;
                return true;
            default:
                protocol = NetProtocol.Any;
                return false;
        }
    }
}
