using System.Net;
using System.Net.Sockets;
using System.Security.Principal;
using CrioFire.Core;

namespace CrioFire.IntegrationTests;

/// <summary>
/// Port and address rules against the real Windows Filtering Platform. Every rule is narrowed to
/// a test port or to the test peer program, so the rest of the machine (and the test runner's own
/// connections) are never affected.
/// </summary>
public sealed class NetRuleTests : IDisposable
{
    private WfpEngine? _engine;

    public void Dispose()
    {
        if (_engine is not null)
        {
            _engine.Uninstall();
            _engine.Dispose();
        }
    }

    [Fact]
    public async Task PortRuleBlocksOnlyThatPort()
    {
        var engine = Engine();
        using var blockedListener = new LocalListener(IPAddress.Loopback);
        using var otherListener = new LocalListener(IPAddress.Loopback);

        var ids = engine.AddNetRule(Rule(RuleAction.Block, TrafficDirection.Outbound, NetProtocol.Tcp, blockedListener.Port.ToString(System.Globalization.CultureInfo.InvariantCulture)));
        Assert.Equal(2, ids.Count);   // IPv4 and IPv6 outbound

        var blocked = await Peer.ConnectAsync(IPAddress.Loopback, blockedListener.Port);
        Assert.True(blocked.ExitCode != 0, $"The port rule should block port {blockedListener.Port}: {blocked.Output}");
        var other = await Peer.ConnectAsync(IPAddress.Loopback, otherListener.Port);
        Assert.True(other.ExitCode == 0, $"Other ports must still work: {other.Output}");

        Assert.Equal(2, engine.RemoveFilter(ids[0]));   // removing one filter removes the whole rule
        var after = await Peer.ConnectAsync(IPAddress.Loopback, blockedListener.Port);
        Assert.True(after.ExitCode == 0, $"Removing the rule should restore the port: {after.Output}");
    }

    [Fact]
    public async Task PortRangeMatches()
    {
        var engine = Engine();
        using var listener = new LocalListener(IPAddress.Loopback);
        var low = Math.Max(1, listener.Port - 5);
        var high = Math.Min(65535, listener.Port + 5);
        engine.AddNetRule(Rule(RuleAction.Block, TrafficDirection.Outbound, NetProtocol.Any, $"{low}-{high}"));

        var blocked = await Peer.ConnectAsync(IPAddress.Loopback, listener.Port);
        Assert.True(blocked.ExitCode != 0, $"A range containing the port should block it: {blocked.Output}");
    }

    [Fact]
    public async Task AddressBlockMatchesIPv4OnlyAndAddsNoIPv6Filters()
    {
        var engine = Engine();
        SkipIfNoIPv6();
        using var v4 = new LocalListener(IPAddress.Loopback);
        using var v6 = new LocalListener(IPAddress.IPv6Loopback);
        var ports = $"{v4.Port},{v6.Port}";

        var ids = engine.AddNetRule(Rule(RuleAction.Block, TrafficDirection.Outbound, NetProtocol.Tcp, ports, "127.0.0.0/8"));
        Assert.Single(ids);   // only the IPv4 layer: an IPv6 filter without the address would match everything

        var blocked = await Peer.ConnectAsync(IPAddress.Loopback, v4.Port);
        Assert.True(blocked.ExitCode != 0, $"127.0.0.0/8 should be blocked: {blocked.Output}");
        var allowed = await Peer.ConnectAsync(IPAddress.IPv6Loopback, v6.Port);
        Assert.True(allowed.ExitCode == 0, $"::1 is not in 127.0.0.0/8: {allowed.Output}");
    }

    [Fact]
    public async Task IPv6AddressRuleMatches()
    {
        var engine = Engine();
        SkipIfNoIPv6();
        using var v6 = new LocalListener(IPAddress.IPv6Loopback);
        engine.AddNetRule(Rule(RuleAction.Block, TrafficDirection.Outbound, NetProtocol.Tcp, v6.Port.ToString(System.Globalization.CultureInfo.InvariantCulture), "::1"));

        var blocked = await Peer.ConnectAsync(IPAddress.IPv6Loopback, v6.Port);
        Assert.True(blocked.ExitCode != 0, $"::1 should be blocked: {blocked.Output}");
    }

    [Fact]
    public async Task AllowOnOnePortBeatsAProgramBlock()
    {
        var engine = Engine();
        using var allowedPort = new LocalListener(IPAddress.Loopback);
        using var otherPort = new LocalListener(IPAddress.Loopback);

        engine.SetAppRule(Peer.ExePath, RuleAction.Block, TrafficDirection.Outbound);
        engine.AddNetRule(Rule(RuleAction.Allow, TrafficDirection.Outbound, NetProtocol.Tcp, allowedPort.Port.ToString(System.Globalization.CultureInfo.InvariantCulture), app: Peer.ExePath));

        var allowed = await Peer.ConnectAsync(IPAddress.Loopback, allowedPort.Port);
        Assert.True(allowed.ExitCode == 0, $"The program should still reach its allowed port: {allowed.Output}");
        var blocked = await Peer.ConnectAsync(IPAddress.Loopback, otherPort.Port);
        Assert.True(blocked.ExitCode != 0, $"Every other port stays blocked for the program: {blocked.Output}");
    }

    [Fact]
    public async Task InboundLocalPortRuleForOneProgram()
    {
        var engine = Engine();
        var before = await Peer.ListenAndConnectAsync(IPAddress.Loopback);
        Assert.True(before.Connected && before.PeerExitCode == 0, "Baseline inbound connection failed before any rule.");

        // Every local port, but only for the test peer: exercises the local-port range condition inbound.
        engine.AddNetRule(Rule(RuleAction.Block, TrafficDirection.Inbound, NetProtocol.Tcp, "1-65535", app: Peer.ExePath));
        var blocked = await Peer.ListenAndConnectAsync(IPAddress.Loopback);
        Assert.False(blocked.Connected, "Inbound connections to the peer's port should be blocked.");
    }

    [Fact]
    public void ListedRulesParseBackAndIdenticalRulesReplaceEachOther()
    {
        var engine = Engine();
        var rule = Rule(RuleAction.Block, TrafficDirection.Both, NetProtocol.Udp, "5353", "224.0.0.251");
        engine.AddNetRule(rule);
        engine.AddNetRule(rule);   // same rule again: replaced, not doubled

        var filters = engine.ListFilters().Where(f => f.Kind == FilterKind.NetRule).ToList();
        Assert.Equal(2, filters.Count);   // IPv4 outbound + IPv4 inbound
        Assert.All(filters, f => Assert.Equal(rule, f.Net));
        Assert.Equal(2, engine.RemoveAllFilters());
    }

    /// <summary>
    /// A rule for some networks only applies on those. Checked on the runner's real network (not
    /// loopback): connections to a documentation address (203.0.113.9, which goes nowhere) leave
    /// through the network the default route uses. A block rule for that address on that kind of
    /// network stops them; the same rule for the other kinds does not. When it fails, the message
    /// lists what every variant did, so the cause can be read from the run page. (TCP, because a
    /// blocked TCP connect fails at once with "access denied"; a blocked UDP send does not report it.)
    /// </summary>
    [Fact]
    public async Task NetworkScopedRulesApplyOnlyOnThoseNetworks()
    {
        var engine = Engine();
        var current = DefaultRouteNetwork();
        Assert.SkipWhen(current is null, "Could not tell which kind of network the default route uses.");

        async Task<string> Probe(NetworkProfiles? networks)
        {
            if (networks is { } n)
            {
                engine.AddNetRule(Rule(RuleAction.Block, TrafficDirection.Outbound, NetProtocol.Any, null, "203.0.113.9", networks: n));
            }

            try
            {
                return await TcpBlocked() ? "blocked" : "open";
            }
            finally
            {
                engine.RemoveAllFilters();
            }
        }

        var results = new List<(string Name, string Result)>
        {
            ("no rule", await Probe(null)),
            ("every network", await Probe(NetworkProfiles.Any)),
            ("public", await Probe(NetworkProfiles.Public)),
            ("private", await Probe(NetworkProfiles.Private)),
            ("domain", await Probe(NetworkProfiles.Domain)),
        };
        var report = $"Default route network: {NetworkScope.Text(current!.Value)}. " + string.Join("; ", results.Select(r => $"{r.Name}: {r.Result}"));
        string Of(string name) => results.Single(r => r.Name == name).Result;

        Assert.True(Of("no rule") == "open", "Baseline failed. " + report);
        Assert.True(Of("every network") == "blocked", "A rule for every network did not block. " + report);
        Assert.True(Of(NetworkScope.Text(current.Value)) == "blocked", "The rule for this kind of network did not block. " + report);
        foreach (var other in Kinds.Where(o => o != NetworkScope.Text(current.Value)))
        {
            Assert.True(Of(other) == "open", $"The rule for {other} networks blocked on a {NetworkScope.Text(current.Value)} network. " + report);
        }
    }

    private static readonly string[] Kinds = ["public", "private", "domain"];

    /// <summary>A blocked TCP connect fails at once with "access denied"; an allowed one to nowhere just times out.</summary>
    private static async Task<bool> TcpBlocked()
    {
        using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(2));
        try
        {
            await socket.ConnectAsync(new IPEndPoint(IPAddress.Parse("203.0.113.9"), 9), timeout.Token);
            return false;
        }
        catch (SocketException ex) when (ex.SocketErrorCode == SocketError.AccessDenied)
        {
            return true;
        }
        catch (Exception ex) when (ex is OperationCanceledException or SocketException)
        {
            return false;
        }
    }

    /// <summary>The kind of network the IPv4 default route leaves through, as Windows classifies it.</summary>
    internal static NetworkProfiles? DefaultRouteNetwork()
    {
        var script = "(Get-NetRoute -DestinationPrefix 0.0.0.0/0 | Sort-Object RouteMetric | Select-Object -First 1 | Get-NetConnectionProfile).NetworkCategory";
        using var process = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("powershell.exe", $"-NoProfile -NonInteractive -Command \"{script}\"")
        {
            RedirectStandardOutput = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        });
        var output = process?.StandardOutput.ReadToEnd().Trim() ?? string.Empty;
        process?.WaitForExit();
        return output switch
        {
            "Public" => NetworkProfiles.Public,
            "Private" => NetworkProfiles.Private,
            "DomainAuthenticated" => NetworkProfiles.Domain,
            _ => null,
        };
    }

    private static NetRule Rule(RuleAction action, TrafficDirection direction, NetProtocol protocol, string? ports, string? addresses = null, string? app = null,
        NetworkProfiles networks = NetworkProfiles.Any) =>
        NetRule.Create(action, direction, protocol, ports, addresses, app, out var error, networks) ?? throw new InvalidOperationException(error);

    private WfpEngine Engine()
    {
        Assert.SkipUnless(Environment.GetEnvironmentVariable("CRIOFIRE_INTEGRATION") == "1",
            "Set CRIOFIRE_INTEGRATION=1 to run tests that change the firewall.");
        Assert.True(IsAdministrator(), "CRIOFIRE_INTEGRATION=1 is set, but firewall tests need an administrator terminal.");

        if (_engine is null)
        {
            _engine = WfpEngine.Open();
            _engine.Uninstall();
            _engine.Install();
        }

        return _engine;
    }

    private static void SkipIfNoIPv6() => Assert.SkipUnless(Socket.OSSupportsIPv6, "IPv6 is not available on this machine.");

    private static bool IsAdministrator()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }
}
