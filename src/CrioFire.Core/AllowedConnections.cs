using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;

namespace CrioFire.Core;

/// <summary>Why a connection was allowed.</summary>
public enum AllowReason
{
    /// <summary>The user's allow rule for the program.</summary>
    Rule,

    /// <summary>The user's port/address rule.</summary>
    NetRule,

    /// <summary>The user's allow rule for a Windows service.</summary>
    ServiceRule,

    /// <summary>CrioFire's automatic permit for services in svchost.exe (Ask/Allow-list modes).</summary>
    WindowsServices,

    /// <summary>CrioFire's automatic permit for the Windows kernel (Ask/Allow-list modes).</summary>
    WindowsKernel,

    /// <summary>Traffic that stays on this PC (loopback) is never blocked by the mode.</summary>
    Loopback,

    /// <summary>No CrioFire rule applied: Learning mode, or inbound traffic left to Windows Firewall.</summary>
    NoRule,

    /// <summary>The panic switch is on "allow everything": rules are paused.</summary>
    Paused,
}

public static class AllowReasons
{
    /// <summary>Allowed without anyone making a rule for it.</summary>
    public static bool IsAutomatic(AllowReason reason) =>
        reason is AllowReason.WindowsServices or AllowReason.WindowsKernel or AllowReason.Loopback or AllowReason.NoRule;

    public static bool IsAutomatic(string? reason) => Enum.TryParse<AllowReason>(reason, out var r) && IsAutomatic(r);

    public static AllowReason Classify(CrioFireFilter? filter, bool isLoopback)
    {
        if (filter is not null)
        {
            switch (filter.Kind)
            {
                case FilterKind.AppRule:
                    return AllowReason.Rule;
                case FilterKind.NetRule:
                    return AllowReason.NetRule;
                case FilterKind.ServiceRule:
                    return AllowReason.ServiceRule;
                case FilterKind.Panic:
                    return AllowReason.Paused;
                case FilterKind.BuiltInAllow:
                    return string.Equals(filter.BuiltIn, AutoRulePolicy.WindowsKernel, StringComparison.OrdinalIgnoreCase)
                        ? AllowReason.WindowsKernel
                        : AllowReason.WindowsServices;
            }
        }

        return isLoopback ? AllowReason.Loopback : AllowReason.NoRule;
    }

    /// <summary>
    /// Finds the CrioFire filter that let a connection through. The engine's allow event names the
    /// filter that made the final decision, which is often another firewall's (e.g. Windows
    /// Firewall's loopback permit), so the connection is also matched against CrioFire's own allow
    /// filters, the heaviest first, as the filtering engine weighs them.
    /// </summary>
    public static CrioFireFilter? Resolve(IReadOnlyList<CrioFireFilter> filters, AllowedConnection connection)
    {
        ArgumentNullException.ThrowIfNull(filters);
        ArgumentNullException.ThrowIfNull(connection);
        var exact = filters.FirstOrDefault(f => f.FilterId == connection.FilterId);
        if (exact is not null && Weight(exact, connection, ignoreMatch: true) >= 0)
        {
            return exact;
        }

        CrioFireFilter? best = null;
        var bestWeight = -1;
        foreach (var f in filters)
        {
            if (f.Layer is null || f.Layer.Direction != connection.Direction)
            {
                continue;
            }

            var weight = Weight(f, connection, ignoreMatch: false);
            if (weight > bestWeight)
            {
                best = f;
                bestWeight = weight;
            }
        }

        return best;
    }

    /// <summary>The filter's weight if it is an allow filter that covers the connection, otherwise -1.</summary>
    private static int Weight(CrioFireFilter f, AllowedConnection c, bool ignoreMatch) => f.Kind switch
    {
        FilterKind.AppRule when f.Rule is { Action: RuleAction.Allow } r && (ignoreMatch || SameApp(r.AppPath, c.AppPath)) => 10,
        FilterKind.ServiceRule when f.Service is { Action: RuleAction.Allow } s && (ignoreMatch || HasService(c.Service, s.ServiceName)) => 11,
        FilterKind.NetRule when f.Net is { Action: RuleAction.Allow } n && (ignoreMatch || Matches(n, c)) => n.Weight,
        FilterKind.Panic when f.Panic == PanicState.AllowAll => int.MaxValue,   // matches everything, above every rule
        FilterKind.BuiltInAllow when ignoreMatch || BuiltInCovers(f.BuiltIn, c.AppPath) => 5,
        _ => -1,
    };

    private static bool SameApp(string? a, string? b) => KnownApps.SameApp(a, b);

    private static bool BuiltInCovers(string? builtIn, string? app) => builtIn?.ToLowerInvariant() switch
    {
        AutoRulePolicy.WindowsKernel => KnownApps.IsKernel(app),
        KnownApps.CrioFireServiceRule => app?.EndsWith(@"" + KnownApps.CrioFireService, StringComparison.OrdinalIgnoreCase) == true,
        _ => KnownApps.IsServiceHost(app),
    };

    private static bool HasService(string? services, string name) =>
        services is not null && services.Split(',', StringSplitOptions.TrimEntries).Contains(name, StringComparer.OrdinalIgnoreCase);

    private static bool Matches(NetRule n, AllowedConnection c)
    {
        if (n.AppPath is not null && !SameApp(n.AppPath, c.AppPath))
        {
            return false;
        }

        var ports = n.PortList;
        var tcpOrUdp = c.Protocol is ProtocolType.Tcp or ProtocolType.Udp;
        var protocolOk = n.Protocol switch
        {
            NetProtocol.Tcp => c.Protocol == ProtocolType.Tcp,
            NetProtocol.Udp => c.Protocol == ProtocolType.Udp,
            _ => ports.Count == 0 || tcpOrUdp,
        };
        if (!protocolOk)
        {
            return false;
        }

        if (ports.Count > 0)
        {
            var port = c.ServicePort;
            if (!ports.Any(p => port >= p.Low && port <= p.High))
            {
                return false;
            }
        }

        var addresses = n.AddressList;
        return addresses.Count == 0 || (c.Remote is not null && addresses.Any(a => a.Contains(c.Remote.Address)));
    }

    /// <summary>Loopback as Windows treats it: the flag on the event, a loopback address, or a connection to this PC's own address.</summary>
    public static bool IsLoopback(bool flag, IPEndPoint? local, IPEndPoint? remote) =>
        flag
        || (remote is not null && IPAddress.IsLoopback(remote.Address.IsIPv4MappedToIPv6 ? remote.Address.MapToIPv4() : remote.Address))
        || (local is not null && remote is not null && local.Address.Equals(remote.Address));

    /// <summary>A short label for lists.</summary>
    public static string Label(string? reason, string? direction) => reason switch
    {
        nameof(AllowReason.Rule) => "Your rule",
        nameof(AllowReason.NetRule) => "Your port/address rule",
        nameof(AllowReason.ServiceRule) => "Your service rule",
        nameof(AllowReason.WindowsServices) => "Automatic: Windows services",
        nameof(AllowReason.WindowsKernel) => "Automatic: Windows kernel",
        nameof(AllowReason.Loopback) => "Automatic: local only",
        nameof(AllowReason.NoRule) when direction == "in" => "No rule: Windows Firewall decides",
        nameof(AllowReason.NoRule) => "No rule: Learning mode",
        nameof(AllowReason.Paused) => "Panic: rules paused",
        _ => reason ?? "Unknown",
    };
}

/// <summary>One connection the Windows Filtering Platform allowed.</summary>
/// <param name="Rule">The CrioFire filter that allowed it, or null when none of ours applied.</param>
/// <param name="Service">For svchost.exe: the service(s) owning the socket, when it could be found.</param>
public sealed record AllowedConnection(
    DateTime TimeUtc,
    string? AppPath,
    ProtocolType Protocol,
    IPEndPoint? Local,
    IPEndPoint? Remote,
    TrafficDirection Direction,
    bool IsLoopback,
    ulong FilterId,
    CrioFireFilter? Rule,
    string? Service = null)
{
    public AllowReason Reason => AllowReasons.Classify(Rule, IsLoopback);

    public string ProtocolName => Protocol switch
    {
        ProtocolType.Tcp => "TCP",
        ProtocolType.Udp => "UDP",
        ProtocolType.Icmp => "ICMP",
        ProtocolType.IcmpV6 => "ICMPv6",
        _ => ((int)Protocol).ToString(CultureInfo.InvariantCulture),
    };

    /// <summary>The port that identifies the service: the remote port outbound, the local port inbound.</summary>
    public int ServicePort => Direction == TrafficDirection.Inbound ? Local?.Port ?? 0 : Remote?.Port ?? 0;
}

/// <summary>
/// Allowed connections summed per minute and per (program, service, direction, protocol, remote
/// address, port, reason): one line in allowed.log. Allowed traffic is far busier than blocked
/// traffic, so it is not logged one connection per line.
/// </summary>
public sealed record AllowedSummary(
    DateTime MinuteUtc,
    string? App,
    string? Service,
    string Protocol,
    string Direction,
    string? Remote,
    int Port,
    string Reason,
    int Count)
{
    public static IReadOnlyList<AllowedSummary> Aggregate(IEnumerable<AllowedConnection> connections)
    {
        ArgumentNullException.ThrowIfNull(connections);
        return connections
            .GroupBy(c => (
                Minute: new DateTime(c.TimeUtc.Ticks - (c.TimeUtc.Ticks % TimeSpan.TicksPerMinute), DateTimeKind.Utc),
                App: c.AppPath ?? string.Empty,
                Service: c.Service ?? string.Empty,
                c.ProtocolName,
                Direction: c.Direction == TrafficDirection.Inbound ? "in" : "out",
                Remote: c.Remote?.Address.ToString() ?? string.Empty,
                Port: c.ServicePort,
                Reason: c.Reason.ToString()))
            .Select(g => new AllowedSummary(
                g.Key.Minute,
                g.Key.App.Length == 0 ? null : g.Key.App,
                g.Key.Service.Length == 0 ? null : g.Key.Service,
                g.Key.ProtocolName,
                g.Key.Direction,
                g.Key.Remote.Length == 0 ? null : g.Key.Remote,
                g.Key.Port,
                g.Key.Reason,
                g.Count()))
            .OrderBy(s => s.MinuteUtc)
            .ToList();
    }

    public string ToJsonLine()
    {
        using var stream = new MemoryStream();
        using (var w = new Utf8JsonWriter(stream))
        {
            w.WriteStartObject();
            w.WriteString("time", MinuteUtc.ToString("O", CultureInfo.InvariantCulture));
            w.WriteBoolean("allowed", true);
            w.WriteString("app", App);
            if (Service is not null)
            {
                w.WriteString("service", Service);
            }

            w.WriteString("protocol", Protocol);
            w.WriteString("direction", Direction);
            w.WriteString("remote", Remote);
            w.WriteNumber("port", Port);
            w.WriteString("reason", Reason);
            w.WriteNumber("count", Count);
            w.WriteEndObject();
        }

        return Encoding.UTF8.GetString(stream.ToArray());
    }
}

/// <summary>Allowed traffic over a time window, grouped for the Activity list.</summary>
public sealed record AllowedGroup(
    DateTime FirstUtc,
    DateTime LastUtc,
    string? App,
    string? Service,
    string? Protocol,
    string? Direction,
    string? Remote,
    int Port,
    string? Reason,
    int Count)
{
    public const int MaxGroups = 2000;

    /// <summary>Groups allowed log entries; newest first, at most <see cref="MaxGroups"/>.</summary>
    public static List<AllowedGroup> From(IEnumerable<LoggedEvent> events, bool includeLoopback = true)
    {
        ArgumentNullException.ThrowIfNull(events);
        return events
            .Where(e => e.Allowed && (includeLoopback || e.Reason != nameof(AllowReason.Loopback)))
            .GroupBy(e => (
                App: e.App ?? string.Empty,
                Service: e.Service ?? string.Empty,
                Protocol: e.Protocol ?? string.Empty,
                Direction: e.Direction ?? string.Empty,
                Remote: e.Remote ?? string.Empty,
                e.Port,
                Reason: e.Reason ?? string.Empty))
            .Select(g => new AllowedGroup(
                g.Min(e => e.TimeUtc),
                g.Max(e => e.TimeUtc),
                Null(g.Key.App),
                Null(g.Key.Service),
                Null(g.Key.Protocol),
                Null(g.Key.Direction),
                Null(g.Key.Remote),
                g.Key.Port,
                Null(g.Key.Reason),
                g.Sum(e => e.Count)))
            .OrderByDescending(g => g.LastUtc)
            .ThenByDescending(g => g.Count)
            .Take(MaxGroups)
            .ToList();
    }

    private static string? Null(string s) => s.Length == 0 ? null : s;
}
