using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Principal;
using CrioFire.Core;

namespace CrioFire.IntegrationTests;

/// <summary>
/// Real tests of Ask/Allow-list mode: programs without a rule lose outbound internet access,
/// allowed programs, loopback and Windows services (DNS) keep working, and switching back or
/// panic restores everything. Every program already running is allowed first, so the CI runner
/// itself keeps its connection while the mode is on.
/// </summary>
public sealed class ModeTests : IDisposable
{
    private WfpEngine? _engine;

    private WfpEngine Engine
    {
        get
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
    }

    public void Dispose()
    {
        if (_engine is not null)
        {
            _engine.Uninstall();
            _engine.Dispose();
        }
    }

    [Theory]
    [InlineData(FirewallMode.AllowList)]
    [InlineData(FirewallMode.Ask)]
    public async Task BlockingModeStopsProgramsWithoutARule(FirewallMode mode)
    {
        var engine = Engine;
        var target = await InternetTargetAsync();

        engine.SetMode(mode, RunningProgramsExceptPeer());
        try
        {
            Assert.Equal(mode, engine.GetMode());

            var blocked = await Peer.ConnectAsync(target, 443);
            Assert.True(blocked.ExitCode != 0, $"A program without a rule should be blocked in {mode} mode: {blocked.Output}");

            engine.SetAppRule(Peer.ExePath, RuleAction.Allow, TrafficDirection.Outbound);
            var allowed = await Peer.ConnectAsync(target, 443);
            Assert.True(allowed.ExitCode == 0, $"An allowed program should connect in {mode} mode: {allowed.Output}");

            engine.RemoveAppRules(Peer.ExePath);
            var blockedAgain = await Peer.ConnectAsync(target, 443);
            Assert.True(blockedAgain.ExitCode != 0, $"Removing the allow rule should block again: {blockedAgain.Output}");
        }
        finally
        {
            engine.SetMode(FirewallMode.Learning);
        }

        Assert.Equal(FirewallMode.Learning, engine.GetMode());
        var after = await Peer.ConnectAsync(target, 443);
        Assert.True(after.ExitCode == 0, $"Learning mode should let the program connect again: {after.Output}");
    }

    [Fact]
    public async Task LoopbackAndWindowsServicesKeepWorkingInAllowListMode()
    {
        var engine = Engine;
        await InternetTargetAsync();
        using var listener = new LocalListener(IPAddress.Loopback);

        engine.SetMode(FirewallMode.AllowList, RunningProgramsExceptPeer());
        try
        {
            // Loopback is exempt from the catch-all block.
            var local = await Peer.ConnectAsync(IPAddress.Loopback, listener.Port);
            Assert.True(local.ExitCode == 0, $"Loopback should stay allowed: {local.Output}");

            // Name resolution goes through the DNS Client service in svchost.exe: the built-in permit must
            // cover it. These names are unlikely to be cached on the machine, so a real query is made.
            foreach (var name in new[] { "one.one.one.one", "dns.google" })
            {
                var resolved = await Dns.GetHostAddressesAsync(name, TestContext.Current.CancellationToken);
                Assert.NotEmpty(resolved);
            }
        }
        finally
        {
            engine.SetMode(FirewallMode.Learning);
        }
    }

    [Fact]
    public async Task ExplicitBlockRuleBeatsAnAllowedSnapshot()
    {
        var engine = Engine;
        var target = await InternetTargetAsync();

        // The peer has a block rule; switching mode with "allow running programs" must not override it.
        engine.SetAppRule(Peer.ExePath, RuleAction.Block, TrafficDirection.Outbound);
        engine.SetMode(FirewallMode.Ask, [.. RunningProgramsExceptPeer(), Peer.ExePath]);
        try
        {
            var result = await Peer.ConnectAsync(target, 443);
            Assert.True(result.ExitCode != 0, $"The explicit block rule must still apply: {result.Output}");
            Assert.Contains(engine.ListFilters(), f => f.Rule?.Action == RuleAction.Block);
            Assert.DoesNotContain(engine.ListFilters(), f => f.Rule is { Action: RuleAction.Allow } r && string.Equals(r.AppPath, Peer.ExePath, StringComparison.OrdinalIgnoreCase));
        }
        finally
        {
            engine.SetMode(FirewallMode.Learning);
        }
    }

    [Fact]
    public async Task BlockedByModeIsReportedAsCrioFire()
    {
        var engine = Engine;
        var target = await InternetTargetAsync();
        var start = DateTime.UtcNow.AddSeconds(-2);

        engine.SetMode(FirewallMode.AllowList, RunningProgramsExceptPeer());
        try
        {
            var attempt = await Peer.ConnectAsync(target, 443);
            Assert.True(attempt.ExitCode != 0, $"Should be blocked: {attempt.Output}");

            BlockedConnection? hit = null;
            for (var i = 0; i < 40 && hit is null; i++)
            {
                hit = engine.ReadBlockedConnections(start).FirstOrDefault(e => e.Remote?.Port == 443 && string.Equals(e.AppPath, Peer.ExePath, StringComparison.OrdinalIgnoreCase));
                if (hit is null)
                {
                    await Task.Delay(250, TestContext.Current.CancellationToken);
                }
            }

            Assert.NotNull(hit);
            Assert.Equal(FilterKind.DefaultBlock, hit.Rule!.Kind);
            Assert.Equal(TrafficDirection.Outbound, hit.Direction);
        }
        finally
        {
            engine.SetMode(FirewallMode.Learning);
        }
    }

    [Fact]
    public void PanicRemovesTheModeAndUserRules()
    {
        var engine = Engine;
        engine.SetAppRule(Peer.ExePath, RuleAction.Allow, TrafficDirection.Outbound);
        engine.SetMode(FirewallMode.AllowList);
        Assert.Contains(engine.ListFilters(), f => f.Kind == FilterKind.BuiltInAllow);

        engine.RemoveAllFilters();

        Assert.Equal(FirewallMode.Learning, engine.GetMode());
        Assert.Empty(engine.ListFilters());
    }

    [Fact]
    public async Task PanicAllowPausesRulesAndOffBringsThemBack()
    {
        var engine = Engine;
        var target = await InternetTargetAsync();
        engine.SetAppRule(Peer.ExePath, RuleAction.Block, TrafficDirection.Outbound);
        engine.SetMode(FirewallMode.Ask, RunningProgramsExceptPeer());
        var rules = engine.ListFilters().Count;
        try
        {
            var blocked = await Peer.ConnectAsync(target, 443);
            Assert.True(blocked.ExitCode != 0, $"The block rule should apply before panic: {blocked.Output}");

            Assert.Equal(4, engine.SetPanic(PanicState.AllowAll));
            Assert.Equal(PanicState.AllowAll, engine.GetPanic());
            var paused = await Peer.ConnectAsync(target, 443);
            Assert.True(paused.ExitCode == 0, $"Panic 'allow everything' should let a blocked program connect: {paused.Output}");

            // Nothing was deleted: the same rules and mode are still there.
            Assert.Equal(rules, engine.ListFilters().Count(f => f.Kind != FilterKind.Panic));
            Assert.Equal(FirewallMode.Ask, engine.GetMode());

            Assert.Equal(0, engine.SetPanic(PanicState.Off));
            Assert.Equal(PanicState.Off, engine.GetPanic());
            var again = await Peer.ConnectAsync(target, 443);
            Assert.True(again.ExitCode != 0, $"The block rule should apply again after panic: {again.Output}");
        }
        finally
        {
            engine.SetPanic(PanicState.Off);
            engine.SetMode(FirewallMode.Learning);
            engine.RemoveAppRules(Peer.ExePath);
        }
    }

    [Fact]
    public async Task OrganizationRulesWinOverTheUsersButNotOverPanicBlock()
    {
        var engine = Engine;
        using var listener = new LocalListener(IPAddress.Loopback);
        try
        {
            // The user blocks, the organization allows: the organization's hard permit wins.
            engine.SetAppRule(Peer.ExePath, RuleAction.Block, TrafficDirection.Outbound);
            engine.Managed(() => engine.SetAppRule(Peer.ExePath, RuleAction.Allow, TrafficDirection.Outbound));
            var allowed = await Peer.ConnectAsync(IPAddress.Loopback, listener.Port);
            Assert.True(allowed.ExitCode == 0, $"An organization allow should beat a user block: {allowed.Output}");

            // The user allows, the organization blocks: the block wins.
            engine.SetAppRule(Peer.ExePath, RuleAction.Allow, TrafficDirection.Outbound);
            engine.Managed(() => engine.SetAppRule(Peer.ExePath, RuleAction.Block, TrafficDirection.Outbound));
            var blocked = await Peer.ConnectAsync(IPAddress.Loopback, listener.Port);
            Assert.True(blocked.ExitCode != 0, $"An organization block should beat a user allow: {blocked.Output}");

            // User removals, and "remove all rules", leave the organization's rules alone.
            engine.RemoveAppRules(Peer.ExePath);
            engine.RemoveAllFilters();
            Assert.Contains(engine.ListFilters(), f => f.Managed && f.Rule?.AppPath == Peer.ExePath);
            Assert.DoesNotContain(engine.ListFilters(), f => !f.Managed && f.Rule?.AppPath == Peer.ExePath);

            // Panic "block everything" still beats an organization allow.
            engine.Managed(() => engine.SetAppRule(Peer.ExePath, RuleAction.Allow, TrafficDirection.Outbound));
            var target = await InternetTargetAsync();
            engine.SetPanic(PanicState.BlockAll);
            var panicked = await Peer.ConnectAsync(target, 443);
            engine.SetPanic(PanicState.Off);
            Assert.True(panicked.ExitCode != 0, $"Panic should block even organization-allowed programs: {panicked.Output}");

            Assert.True(engine.ClearManaged() > 0);
            Assert.DoesNotContain(engine.ListFilters(), f => f.Managed);
        }
        finally
        {
            engine.SetPanic(PanicState.Off);
            engine.ClearManaged();
            engine.RemoveAppRules(Peer.ExePath);
        }
    }

    [Fact]
    public async Task PanicBlockStopsEvenAllowedProgramsButNotLoopback()
    {
        var engine = Engine;
        var target = await InternetTargetAsync();
        using var listener = new LocalListener(IPAddress.Loopback);
        engine.SetAppRule(Peer.ExePath, RuleAction.Allow, TrafficDirection.Outbound);
        try
        {
            // Established connections (like the CI runner's own) are not cut: only new ones are refused.
            Assert.Equal(4, engine.SetPanic(PanicState.BlockAll));
            var blocked = await Peer.ConnectAsync(target, 443);
            var local = await Peer.ConnectAsync(IPAddress.Loopback, listener.Port);
            engine.SetPanic(PanicState.Off);

            Assert.True(blocked.ExitCode != 0, $"Panic 'block everything' should beat an allow rule: {blocked.Output}");
            Assert.True(local.ExitCode == 0, $"Loopback should keep working during panic: {local.Output}");

            var after = await Peer.ConnectAsync(target, 443);
            Assert.True(after.ExitCode == 0, $"The program should connect again after panic: {after.Output}");

            // Removing every rule also ends panic.
            engine.SetPanic(PanicState.BlockAll);
            engine.RemoveAllFilters();
            Assert.Equal(PanicState.Off, engine.GetPanic());
        }
        finally
        {
            engine.SetPanic(PanicState.Off);
            engine.RemoveAppRules(Peer.ExePath);
        }
    }

    [Fact]
    public void SwitchingModesReplacesTheCatchAllFilters()
    {
        var engine = Engine;
        engine.SetMode(FirewallMode.Ask);
        var askCount = engine.ListFilters().Count;
        engine.SetMode(FirewallMode.AllowList);

        Assert.Equal(FirewallMode.AllowList, engine.GetMode());
        Assert.Equal(askCount, engine.ListFilters().Count);
        Assert.Equal(2, engine.ListFilters().Count(f => f.Kind == FilterKind.DefaultBlock));
        engine.SetMode(FirewallMode.Learning);
        Assert.Empty(engine.ListFilters());
    }

    private static async Task<IPAddress> InternetTargetAsync()
    {
        var addresses = await Dns.GetHostAddressesAsync("github.com", TestContext.Current.CancellationToken);
        var address = addresses.First(a => a.AddressFamily == AddressFamily.InterNetwork);
        var before = await Peer.ConnectAsync(address, 443);
        Assert.SkipUnless(before.ExitCode == 0, $"No internet access from this machine ({before.Output}).");
        return address;
    }

    /// <summary>
    /// The local-network automatic rule lets programs without a rule reach private addresses in Ask
    /// mode, on home and work networks only. A private address that answers nobody (192.168.255.254)
    /// tells them apart: blocked fails at once ("access denied"), allowed just times out. On a public
    /// network (as CI runners are) the rule must not open anything.
    /// </summary>
    [Fact]
    public async Task TheLocalNetworkRuleOpensHomeAndWorkNetworksOnly()
    {
        var engine = Engine;
        var network = NetRuleTests.DefaultRouteNetwork();
        Assert.SkipWhen(network is null, "Could not tell which kind of network the default route uses.");
        var lanAddress = IPAddress.Parse("192.168.255.254");
        var on = new AutoRulePolicy();
        on.Set(AutoRulePolicy.LocalNetwork, true);

        try
        {
            engine.SetMode(FirewallMode.Ask, RunningProgramsExceptPeer(), new AutoRulePolicy());
            var off = await Peer.ConnectAsync(lanAddress, 9);
            Assert.True(off.Output.Contains("AccessDenied", StringComparison.Ordinal), $"Without the rule, Ask mode should block the local address: {off.Output}");

            engine.SetMode(FirewallMode.Ask, RunningProgramsExceptPeer(), on);
            Assert.Equal(2, engine.ListFilters().Count(f => f.BuiltIn == AutoRulePolicy.LocalNetwork));   // IPv4 and IPv6
            var result = await Peer.ConnectAsync(lanAddress, 9);
            if (network == NetworkProfiles.Public)
            {
                Assert.True(result.Output.Contains("AccessDenied", StringComparison.Ordinal), $"On a public network the local-network rule must not apply: {result.Output}");
            }
            else
            {
                Assert.False(result.Output.Contains("AccessDenied", StringComparison.Ordinal), $"On a {NetworkScope.Text(network!.Value)} network the local-network rule should apply: {result.Output}");
            }
        }
        finally
        {
            engine.SetMode(FirewallMode.Learning);
        }
    }

    internal static List<string> RunningProgramsExceptPeer()
    {
        var paths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var process in Process.GetProcesses())
        {
            using (process)
            {
                try
                {
                    if (process.MainModule?.FileName is { Length: > 0 } path)
                    {
                        paths.Add(path);
                    }
                }
                catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException or NotSupportedException)
                {
                }
            }
        }

        if (Environment.ProcessPath is { } self)
        {
            paths.Add(self);
        }

        paths.Remove(Peer.ExePath);
        return [.. paths];
    }

    private static bool IsAdministrator()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }
}
