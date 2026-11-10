using System.Net;
using System.Security.Principal;
using CrioFire.Core;

namespace CrioFire.IntegrationTests;

/// <summary>
/// End-to-end tests against the real Windows Filtering Platform. Each test starts from a clean
/// CrioFire install and removes everything it added. They skip unless run as administrator with
/// CRIOFIRE_INTEGRATION=1, because they change the machine's firewall.
/// </summary>
public sealed class FirewallTests : IDisposable
{
    public static readonly TheoryData<string> Loopbacks = new() { "127.0.0.1", "::1" };

    private WfpEngine? _engine;

    private WfpEngine Engine
    {
        get
        {
            Assert.SkipUnless(Environment.GetEnvironmentVariable("CRIOFIRE_INTEGRATION") == "1",
                "Set CRIOFIRE_INTEGRATION=1 to run tests that change the firewall.");
            Assert.SkipUnless(IsAdministrator(), "Firewall tests need administrator rights.");

            if (_engine is null)
            {
                _engine = WfpEngine.Open();
                _engine.Uninstall();   // start clean even if an earlier run was interrupted
                _engine.Install();
            }

            return _engine;
        }
    }

    public void Dispose()
    {
        if (_engine is not null)
        {
            _engine.Uninstall();
            _engine.Dispose();
        }
    }

    [Fact]
    public void InstallIsIdempotentAndUninstallRemovesEverything()
    {
        var engine = Engine;
        Assert.True(engine.IsInstalled());
        engine.Install();
        Assert.True(engine.IsInstalled());

        engine.SetAppRule(Peer.ExePath, RuleAction.Block, TrafficDirection.Both);
        engine.Uninstall();

        Assert.False(engine.IsInstalled());
        Assert.Empty(engine.ListFilters());
        engine.Install();   // leave it installed for Dispose
    }

    [Theory]
    [MemberData(nameof(Loopbacks))]
    public async Task OutboundBlockStopsTheAppAndUnblockRestoresIt(string loopback)
    {
        var engine = Engine;
        var address = IPAddress.Parse(loopback);
        SkipIfNoIPv6(address);
        using var listener = new LocalListener(address);

        var before = await Peer.ConnectAsync(address, listener.Port);
        Assert.True(before.ExitCode == 0, $"Baseline connection failed before any rule: {before.Output}");

        engine.SetAppRule(Peer.ExePath, RuleAction.Block, TrafficDirection.Outbound);
        var blocked = await Peer.ConnectAsync(address, listener.Port);
        Assert.True(blocked.ExitCode != 0, $"Connection should be blocked but got: {blocked.Output}");

        Assert.Equal(2, engine.RemoveAppRules(Peer.ExePath));
        var after = await Peer.ConnectAsync(address, listener.Port);
        Assert.True(after.ExitCode == 0, $"Connection should work again after unblocking: {after.Output}");
    }

    [Fact]
    public async Task OutboundBlockStopsInternetTraffic()
    {
        var engine = Engine;
        var addresses = await Dns.GetHostAddressesAsync("github.com");
        var address = addresses.First(a => a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork);

        var before = await Peer.ConnectAsync(address, 443);
        Assert.SkipUnless(before.ExitCode == 0, $"No internet access from this machine ({before.Output}).");

        engine.SetAppRule(Peer.ExePath, RuleAction.Block, TrafficDirection.Outbound);
        var blocked = await Peer.ConnectAsync(address, 443);
        Assert.True(blocked.ExitCode != 0, $"Internet connection should be blocked but got: {blocked.Output}");

        engine.RemoveAppRules(Peer.ExePath);
        var after = await Peer.ConnectAsync(address, 443);
        Assert.True(after.ExitCode == 0, $"Internet connection should work again: {after.Output}");
    }

    [Theory]
    [MemberData(nameof(Loopbacks))]
    public async Task InboundBlockStopsConnectionsToTheApp(string loopback)
    {
        var engine = Engine;
        var address = IPAddress.Parse(loopback);
        SkipIfNoIPv6(address);

        var before = await Peer.ListenAndConnectAsync(address);
        Assert.True(before.Connected && before.PeerExitCode == 0, "Baseline inbound connection failed before any rule.");

        engine.SetAppRule(Peer.ExePath, RuleAction.Block, TrafficDirection.Inbound);
        var blocked = await Peer.ListenAndConnectAsync(address);
        Assert.False(blocked.Connected, "Inbound connection should be blocked.");
        Assert.NotEqual(0, blocked.PeerExitCode);

        engine.RemoveAppRules(Peer.ExePath);
        var after = await Peer.ListenAndConnectAsync(address);
        Assert.True(after.Connected && after.PeerExitCode == 0, "Inbound connection should work again after unblocking.");
    }

    [Fact]
    public async Task OutboundRuleDoesNotAffectInbound()
    {
        var engine = Engine;
        engine.SetAppRule(Peer.ExePath, RuleAction.Block, TrafficDirection.Outbound);

        var inbound = await Peer.ListenAndConnectAsync(IPAddress.Loopback);
        Assert.True(inbound.Connected, "An outbound-only rule must not block inbound connections.");
    }

    [Fact]
    public void ListShowsParsedRulesAndSetReplacesEarlierRules()
    {
        var engine = Engine;
        engine.SetAppRule(Peer.ExePath, RuleAction.Block, TrafficDirection.Both);
        var filters = engine.ListFilters();
        Assert.Equal(4, filters.Count);
        Assert.All(filters, f =>
        {
            Assert.NotNull(f.Rule);
            Assert.Equal(Peer.ExePath, f.Rule!.AppPath, ignoreCase: true);
            Assert.Equal(RuleAction.Block, f.Rule.Action);
            Assert.NotNull(f.Layer);
        });

        engine.SetAppRule(Peer.ExePath, RuleAction.Block, TrafficDirection.Both);
        Assert.Equal(4, engine.ListFilters().Count);
    }

    [Fact]
    public void RemoveFilterRefusesFiltersCrioFireDoesNotOwn()
    {
        var engine = Engine;
        Assert.Throws<InvalidOperationException>(() => engine.RemoveFilter(ulong.MaxValue));

        var ids = engine.SetAppRule(Peer.ExePath, RuleAction.Block, TrafficDirection.Outbound);
        engine.RemoveFilter(ids[0]);
        Assert.Single(engine.ListFilters());
    }

    [Fact]
    public async Task PanicRemovesEveryRule()
    {
        var engine = Engine;
        var address = IPAddress.Loopback;
        using var listener = new LocalListener(address);

        engine.SetAppRule(Peer.ExePath, RuleAction.Block, TrafficDirection.Both);
        Assert.Equal(4, engine.RemoveAllFilters());
        Assert.Empty(engine.ListFilters());
        Assert.True(engine.IsInstalled());

        var after = await Peer.ConnectAsync(address, listener.Port);
        Assert.True(after.ExitCode == 0, $"Connection should work after panic: {after.Output}");
    }

    [Fact]
    public async Task RulesPersistAcrossEngineSessions()
    {
        var engine = Engine;
        var address = IPAddress.Loopback;
        using var listener = new LocalListener(address);

        engine.SetAppRule(Peer.ExePath, RuleAction.Block, TrafficDirection.Outbound);

        // A different session (like the service restarting) still sees and enforces the rule.
        using (var other = WfpEngine.Open())
        {
            Assert.Equal(2, other.ListFilters().Count);
        }

        var blocked = await Peer.ConnectAsync(address, listener.Port);
        Assert.True(blocked.ExitCode != 0, $"Rule should still be enforced: {blocked.Output}");
    }

    [Fact]
    public void BlockingAMissingProgramFailsCleanly()
    {
        var engine = Engine;
        Assert.Throws<FileNotFoundException>(() =>
            engine.SetAppRule(@"C:\does-not-exist\nothing.exe", RuleAction.Block, TrafficDirection.Outbound));
        Assert.Empty(engine.ListFilters());
    }

    private static void SkipIfNoIPv6(IPAddress address) =>
        Assert.SkipWhen(address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 && !System.Net.Sockets.Socket.OSSupportsIPv6,
            "IPv6 is not available on this machine.");

    private static bool IsAdministrator()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }
}
