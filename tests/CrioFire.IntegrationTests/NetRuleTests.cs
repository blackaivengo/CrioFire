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

    private static NetRule Rule(RuleAction action, TrafficDirection direction, NetProtocol protocol, string? ports, string? addresses = null, string? app = null) =>
        NetRule.Create(action, direction, protocol, ports, addresses, app, out var error) ?? throw new InvalidOperationException(error);

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
