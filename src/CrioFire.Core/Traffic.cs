using System.Globalization;
using System.Net;

namespace CrioFire.Core;

/// <summary>
/// Blocked and allowed connections from the traffic logs, grouped and filtered for the Activity
/// page: one row per program (or service), direction, protocol, remote address, port and reason.
/// </summary>
/// <param name="Allowed">True for allowed traffic, false for blocked.</param>
/// <param name="Why">For blocked traffic the kind of filter (DefaultBlock, AppRule, NetRule, ServiceRule, Panic);
/// for allowed traffic an <see cref="AllowReason"/> name.</param>
/// <param name="Port">The port that names the service: the remote port outbound, the local port inbound.</param>
/// <param name="Local">Blocked traffic only: the local address and port of the last attempt.</param>
/// <param name="FilterId">Blocked traffic only: the CrioFire filter that blocked it.</param>
public sealed record TrafficItem(
    bool Allowed,
    DateTime FirstUtc,
    DateTime LastUtc,
    string? App,
    string? Service,
    string? Protocol,
    string? Direction,
    string? Remote,
    int Port,
    string? Local,
    string? Why,
    ulong FilterId,
    int Count)
{
    /// <summary>A short label for the reason, e.g. "No rule yet" or "Automatic: Windows services".</summary>
    public string WhyLabel => Allowed ? AllowReasons.Label(Why, Direction) : BlockedLabel(Why);

    public static string BlockedLabel(string? kind) => kind switch
    {
        nameof(FilterKind.DefaultBlock) => "No rule yet (mode)",
        nameof(FilterKind.AppRule) => "Your block rule",
        nameof(FilterKind.NetRule) => "Your port/address rule",
        nameof(FilterKind.ServiceRule) => "Your service rule",
        nameof(FilterKind.DomainAddress) => "Your domain rule",
        nameof(FilterKind.Panic) => "Panic: block all",
        _ => "Blocked",
    };
}

/// <summary>One page of <see cref="TrafficItem"/>s.</summary>
/// <param name="Total">Rows matching the filter, on all pages.</param>
/// <param name="Connections">Connections in those rows (rows group repeated connections).</param>
public sealed record TrafficPage(int Total, int Connections, int Offset, List<TrafficItem> Items);

/// <summary>What to show: kind, time, text search, reason group, direction, one program or service, paging.</summary>
/// <param name="Kind">blocked, allowed or all.</param>
/// <param name="Why">A reason group: mine (your rules), norule (no rule yet / Learning), automatic (Windows services and kernel),
/// loopback, panic; or null for all.</param>
/// <param name="Sort">recent (default) or count.</param>
public sealed record TrafficFilter(
    string Kind,
    DateTime FromUtc,
    string? Search = null,
    string? Why = null,
    string? Direction = null,
    string? App = null,
    string? Service = null,
    bool IncludeLoopback = false,
    string? Sort = null,
    int Offset = 0,
    int Limit = 100)
{
    public const int MaxLimit = 500;
}

public static class TrafficQuery
{
    public static IReadOnlyList<string> WhyGroups { get; } = ["mine", "norule", "automatic", "loopback", "panic"];

    public static TrafficPage Run(IEnumerable<LoggedEvent> events, TrafficFilter filter)
    {
        ArgumentNullException.ThrowIfNull(events);
        ArgumentNullException.ThrowIfNull(filter);
        var wantBlocked = filter.Kind is "blocked" or "all";
        var wantAllowed = filter.Kind is "allowed" or "all";

        var rows = events
            .Where(e => DateTime.SpecifyKind(e.TimeUtc, DateTimeKind.Utc) >= filter.FromUtc)
            .Where(e => e.Allowed ? wantAllowed : wantBlocked)
            .Where(e => filter.IncludeLoopback || !(e.Allowed && e.Reason == nameof(AllowReason.Loopback)) || filter.Why == "loopback")
            .Select(Normalize)
            .GroupBy(x => (x.Allowed, x.App, x.Service, x.Protocol, x.Direction, x.Remote, x.Port, x.Why, x.FilterId))
            .Select(g => new TrafficItem(
                g.Key.Allowed,
                g.Min(x => x.Time),
                g.Max(x => x.Time),
                Null(g.Key.App),
                Null(g.Key.Service),
                Null(g.Key.Protocol),
                Null(g.Key.Direction),
                Null(g.Key.Remote),
                g.Key.Port,
                g.MaxBy(x => x.Time).Local,
                Null(g.Key.Why),
                g.Key.FilterId,
                g.Sum(x => x.Count)))
            .Where(i => Matches(i, filter))
            .ToList();

        var sorted = filter.Sort == "count"
            ? rows.OrderByDescending(i => i.Count).ThenByDescending(i => i.LastUtc)
            : rows.OrderByDescending(i => i.LastUtc).ThenByDescending(i => i.Count);
        var limit = Math.Clamp(filter.Limit, 1, TrafficFilter.MaxLimit);
        var lastPage = rows.Count == 0 ? 0 : (rows.Count - 1) / limit * limit;
        var offset = Math.Clamp(filter.Offset, 0, lastPage);
        return new TrafficPage(rows.Count, rows.Sum(i => i.Count), offset, sorted.Skip(offset).Take(limit).ToList());
    }

    /// <summary>Is this reason one of the group's? Groups: mine, norule, automatic, loopback, panic.</summary>
    public static bool InGroup(TrafficItem item, string group)
    {
        ArgumentNullException.ThrowIfNull(item);
        return (group, item.Allowed) switch
        {
            ("mine", false) => item.Why is nameof(FilterKind.AppRule) or nameof(FilterKind.NetRule) or nameof(FilterKind.ServiceRule) or nameof(FilterKind.DomainAddress),
            ("mine", true) => item.Why is nameof(AllowReason.Rule) or nameof(AllowReason.NetRule) or nameof(AllowReason.ServiceRule),
            ("norule", false) => item.Why == nameof(FilterKind.DefaultBlock),
            ("norule", true) => item.Why == nameof(AllowReason.NoRule),
            ("automatic", true) => item.Why is nameof(AllowReason.WindowsServices) or nameof(AllowReason.WindowsKernel) or nameof(AllowReason.LocalNetwork),
            ("loopback", true) => item.Why == nameof(AllowReason.Loopback),
            ("panic", false) => item.Why == nameof(FilterKind.Panic),
            ("panic", true) => item.Why == nameof(AllowReason.Paused),
            _ => false,
        };
    }

    private static bool Matches(TrafficItem i, TrafficFilter f)
    {
        if (f.Why is { Length: > 0 } group && !InGroup(i, group))
        {
            return false;
        }

        if (f.Direction is "in" or "out" && i.Direction != f.Direction)
        {
            return false;
        }

        if (f.App is { Length: > 0 } app && !string.Equals(i.App, app, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (f.Service is { Length: > 0 } service
            && (i.Service is null || !i.Service.Split(',', StringSplitOptions.TrimEntries).Contains(service, StringComparer.OrdinalIgnoreCase)))
        {
            return false;
        }

        if (f.Search is not { Length: > 0 } search)
        {
            return true;
        }

        foreach (var word in search.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var port = i.Port.ToString(CultureInfo.InvariantCulture);
            var hit = Has(i.App, word) || Has(i.Service, word) || Has(i.Remote, word) || Has(i.Protocol, word)
                || Has(i.WhyLabel, word) || Has(i.Local, word) || port == word.TrimStart(':');
            if (!hit)
            {
                return false;
            }
        }

        return true;
    }

    private static bool Has(string? text, string word) => text is not null && text.Contains(word, StringComparison.OrdinalIgnoreCase);

    private static string? Null(string s) => s.Length == 0 ? null : s;

    /// <summary>Blocked lines carry "address:port" endpoints; allowed lines an address and the service port.</summary>
    private static (bool Allowed, DateTime Time, string App, string Service, string Protocol, string Direction, string Remote, int Port, string Why, ulong FilterId, int Count, string? Local)
        Normalize(LoggedEvent e)
    {
        var time = DateTime.SpecifyKind(e.TimeUtc, DateTimeKind.Utc);
        if (e.Allowed)
        {
            return (true, time, e.App ?? string.Empty, e.Service ?? string.Empty, e.Protocol ?? string.Empty, e.Direction ?? string.Empty,
                e.Remote ?? string.Empty, e.Port, e.Reason ?? string.Empty, 0, e.Count, null);
        }

        var remote = IPEndPoint.TryParse(e.Remote ?? string.Empty, out var r) ? r : null;
        var local = IPEndPoint.TryParse(e.Local ?? string.Empty, out var l) ? l : null;
        var port = e.Direction == "in" ? local?.Port ?? 0 : remote?.Port ?? 0;
        return (false, time, e.App ?? string.Empty, string.Empty, e.Protocol ?? string.Empty, e.Direction ?? string.Empty,
            remote?.Address.ToString() ?? e.Remote ?? string.Empty, port, e.Kind ?? string.Empty, e.FilterId, 1, e.Local);
    }
}

/// <summary>Plain-language facts about a port and a remote address, for the details pane.</summary>
public static class NetworkFacts
{
    private static readonly Dictionary<int, string> Ports = new()
    {
        [20] = "FTP data", [21] = "FTP", [22] = "SSH", [23] = "Telnet", [25] = "SMTP (mail)", [53] = "DNS (name lookups)",
        [67] = "DHCP", [68] = "DHCP", [69] = "TFTP", [80] = "HTTP (web)", [88] = "Kerberos", [110] = "POP3 (mail)",
        [123] = "NTP (time sync)", [135] = "Windows RPC", [137] = "NetBIOS name", [138] = "NetBIOS datagram",
        [139] = "NetBIOS session", [143] = "IMAP (mail)", [161] = "SNMP", [389] = "LDAP", [443] = "HTTPS (web)",
        [445] = "SMB (file sharing)", [465] = "SMTPS (mail)", [500] = "IPsec/IKE", [587] = "SMTP submission (mail)",
        [636] = "LDAPS", [853] = "DNS over TLS", [993] = "IMAPS (mail)", [995] = "POP3S (mail)", [1194] = "OpenVPN",
        [1433] = "SQL Server", [1900] = "SSDP/UPnP (device discovery)", [3306] = "MySQL", [3389] = "Remote Desktop",
        [3478] = "STUN (calls, games)", [4500] = "IPsec NAT-T", [5040] = "Windows CDP", [5222] = "XMPP (chat)",
        [5353] = "mDNS (local discovery)", [5355] = "LLMNR (local name lookups)", [5432] = "PostgreSQL", [5900] = "VNC",
        [7680] = "Delivery Optimization", [8080] = "HTTP (alternate)", [8443] = "HTTPS (alternate)", [51820] = "WireGuard",
    };

    /// <summary>"HTTPS (web)" for 443, or null.</summary>
    public static string? PortName(int port) => Ports.GetValueOrDefault(port);

    /// <summary>Where an address is: this PC, the local network, a link-local address, multicast, or the internet.</summary>
    public static string AddressScope(string? address)
    {
        if (!IPAddress.TryParse(address ?? string.Empty, out var ip))
        {
            return "unknown";
        }

        if (ip.IsIPv4MappedToIPv6)
        {
            ip = ip.MapToIPv4();
        }

        if (IPAddress.IsLoopback(ip))
        {
            return "this PC (loopback)";
        }

        var b = ip.GetAddressBytes();
        if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
        {
            return b[0] switch
            {
                10 => "local network (private)",
                172 when b[1] is >= 16 and <= 31 => "local network (private)",
                192 when b[1] == 168 => "local network (private)",
                169 when b[1] == 254 => "link-local (this network segment)",
                100 when b[1] is >= 64 and <= 127 => "carrier-grade NAT (shared)",
                >= 224 and <= 239 => "multicast (local discovery)",
                255 => "broadcast",
                _ => "internet",
            };
        }

        if (ip.IsIPv6LinkLocal)
        {
            return "link-local (this network segment)";
        }

        if (ip.IsIPv6Multicast)
        {
            return "multicast (local discovery)";
        }

        return (b[0] & 0xFE) == 0xFC ? "local network (private)" : "internet";
    }
}
