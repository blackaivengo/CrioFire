using System.Net;
using System.Security.Principal;
using CrioFire.Core;
using CrioFire.Core.Api;

namespace CrioFire.IntegrationTests;

/// <summary>
/// Allowed traffic is recorded with the reason, and automatic, service and kernel rules can be
/// seen and changed, against the real Windows Filtering Platform. Service rules use a service name
/// that does not exist, so they never affect the machine.
/// </summary>
public sealed class VisibilityTests : IDisposable
{
    private const string NoSuchService = "CrioFireTestNoSuchService";
    private readonly string _policyPath = Path.Combine(Path.GetTempPath(), $"criofire-auto-{Guid.NewGuid():N}.txt");
    private WfpEngine? _engine;

    public void Dispose()
    {
        if (_engine is not null)
        {
            _engine.Uninstall();
            _engine.Dispose();
        }

        File.Delete(_policyPath);
    }

    [Fact]
    public async Task AllowedConnectionsAreRecordedWithTheReason()
    {
        var engine = Engine();
        Assert.True(engine.SetAllowedEventCollection(true), "Windows refused to record allowed connections.");
        using var listener = new LocalListener(IPAddress.Loopback);
        var since = DateTime.UtcNow.AddSeconds(-2);

        // A program allow rule (no loopback exemption) is what allows this one.
        engine.SetAppRule(Peer.ExePath, RuleAction.Allow, TrafficDirection.Outbound);
        var byRule = await Peer.ConnectAsync(IPAddress.Loopback, listener.Port);
        Assert.True(byRule.ExitCode == 0, byRule.Output);
        var e = await FindAsync(engine, since, listener.Port);
        Assert.Equal(AllowReason.Rule, e.Reason);
        Assert.Equal(TrafficDirection.Outbound, e.Direction);
        Assert.True(e.IsLoopback);
        Assert.Equal("TCP", e.ProtocolName);

        // Without the rule, Learning mode lets it through as plain loopback traffic.
        engine.RemoveAppRules(Peer.ExePath);
        using var listener2 = new LocalListener(IPAddress.Loopback);
        var since2 = DateTime.UtcNow.AddSeconds(-1);
        var plain = await Peer.ConnectAsync(IPAddress.Loopback, listener2.Port);
        Assert.True(plain.ExitCode == 0, plain.Output);
        var e2 = await FindAsync(engine, since2, listener2.Port);
        Assert.Equal(AllowReason.Loopback, e2.Reason);

        // And the summaries the service writes read back into the allowed list.
        var log = new TrafficLog(Path.Combine(Path.GetTempPath(), $"criofire-allowed-{Guid.NewGuid():N}.log"));
        try
        {
            log.AppendSummaries(AllowedSummary.Aggregate([e, e2]));
            var handler = new ApiHandler(engine, allowedLog: log);
            var response = handler.Handle(new ApiRequest { Op = ApiOps.Allowed, Minutes = 10, IncludeLoopback = true }, canWrite: false);
            Assert.True(response.Ok, response.Error);
            Assert.Contains(response.Allowed!, g => g.Port == listener.Port && g.Reason == nameof(AllowReason.Rule));
        }
        finally
        {
            File.Delete(log.Path);
        }
    }

    [Fact]
    public void ServiceRulesAreAddedListedAndRemoved()
    {
        var engine = Engine();
        var ids = engine.SetServiceRule(NoSuchService, RuleAction.Block, TrafficDirection.Both);
        Assert.Equal(4, ids.Count);

        var filters = engine.ListFilters().Where(f => f.Kind == FilterKind.ServiceRule).ToList();
        Assert.Equal(4, filters.Count);
        Assert.All(filters, f => Assert.Equal(NoSuchService, f.Service!.ServiceName));
        Assert.Equal("block", RuleInfo.From(filters[0]).Action);
        Assert.Equal(NoSuchService, RuleInfo.From(filters[0]).Service);

        // Setting it again replaces the earlier rule in that direction.
        Assert.Equal(2, engine.SetServiceRule(NoSuchService, RuleAction.Allow, TrafficDirection.Outbound).Count);
        Assert.Equal(4, engine.ListFilters().Count(f => f.Kind == FilterKind.ServiceRule));
        Assert.Equal(4, engine.RemoveServiceRules(NoSuchService));
        Assert.DoesNotContain(engine.ListFilters(), f => f.Kind == FilterKind.ServiceRule);
    }

    [Fact]
    public void KernelRulesUseTheSystemAppId()
    {
        var engine = Engine();
        Assert.Equal(2, engine.SetAppRule("system", RuleAction.Allow, TrafficDirection.Inbound).Count);
        var rules = engine.ListFilters().Where(f => f.Rule is not null).ToList();
        Assert.Equal(2, rules.Count);
        Assert.All(rules, f => Assert.Equal(KnownApps.Kernel, f.Rule!.AppPath));
        Assert.Equal(2, engine.RemoveAppRules("System"));
    }

    [Fact]
    public void AutomaticRulesCanBeSwitchedOff()
    {
        var engine = Engine();
        engine.SetMode(FirewallMode.Ask, ModeTests.RunningProgramsExceptPeer(), AutoRulePolicy.Load(_policyPath));
        try
        {
            Assert.Equal(4, engine.ListFilters().Count(f => f.Kind == FilterKind.BuiltInAllow));   // svchost + system, IPv4 + IPv6

            engine.SetAutoRule(AutoRulePolicy.WindowsKernel, false, _policyPath);
            var builtIns = engine.ListFilters().Where(f => f.Kind == FilterKind.BuiltInAllow).ToList();
            Assert.Equal(2, builtIns.Count);
            Assert.All(builtIns, f => Assert.Equal(AutoRulePolicy.WindowsServices, f.BuiltIn));

            var state = engine.GetAutoRules(_policyPath);
            Assert.Contains(state, r => r.Name == AutoRulePolicy.WindowsKernel && !r.Enabled && !r.Active);
            Assert.Contains(state, r => r.Name == AutoRulePolicy.WindowsServices && r.Enabled && r.Active);

            engine.SetAutoRule(AutoRulePolicy.WindowsKernel, true, _policyPath);
            Assert.Equal(4, engine.ListFilters().Count(f => f.Kind == FilterKind.BuiltInAllow));
        }
        finally
        {
            engine.SetMode(FirewallMode.Learning);
        }

        Assert.DoesNotContain(engine.ListFilters(), f => f.Kind == FilterKind.BuiltInAllow);
    }

    /// <summary>The engine can record an event a moment after it happened: poll for a few seconds.</summary>
    private static async Task<AllowedConnection> FindAsync(WfpEngine engine, DateTime since, int port)
    {
        for (var attempt = 0; attempt < 20; attempt++)
        {
            var match = engine.ReadAllowedConnections(since)
                .LastOrDefault(a => a.Remote?.Port == port && string.Equals(a.AppPath, Peer.ExePath, StringComparison.OrdinalIgnoreCase));
            if (match is not null)
            {
                return match;
            }

            await Task.Delay(250);
        }

        var seen = engine.ReadAllowedConnections(since);
        Assert.Fail($"No allowed connection to port {port} from the test peer was recorded. Seen: {seen.Count} events, e.g. "
            + string.Join("; ", seen.Take(5).Select(a => $"{a.AppPath} {a.Remote} {a.Reason}")));
        return null!;
    }

    [Fact]
    public void StoreAppRulesAreKeyedByPackageFamily()
    {
        // A package SID filter can be written whether or not the app is installed, so this never
        // touches a real app on the test machine.
        const string key = "pkg:CrioFire.TestNoSuchApp_0000000000000";
        var engine = Engine();

        var ids = engine.SetAppRule(key, RuleAction.Block, TrafficDirection.Both);

        Assert.True(ids.Count >= 4, $"Expected a package filter per layer, got {ids.Count}.");
        var rules = engine.ListFilters().Where(f => f.Kind == FilterKind.AppRule && f.Rule?.AppPath == key).ToList();
        Assert.Equal(ids.Count, rules.Count);
        Assert.All(rules, r => Assert.Contains("(Store app)", r.Name, StringComparison.Ordinal));

        // Renewing (what the service does after an app update) writes the same rule again.
        var seen = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        Assert.Contains(key, StoreApps.Refresh(engine, seen));
        Assert.Empty(StoreApps.Refresh(engine, seen));
        Assert.Equal(ids.Count, engine.ListFilters().Count(f => f.Rule?.AppPath == key));

        Assert.Equal(ids.Count, engine.RemoveAppRules(key));
        Assert.DoesNotContain(engine.ListFilters(), f => f.Rule?.AppPath == key);
    }

    [Fact]
    public void ExportedRulesComeBackExactlyAfterImport()
    {
        var engine = Engine();
        engine.SetAppRule(Peer.ExePath, RuleAction.Allow, TrafficDirection.Both);
        engine.AddNetRule(NetRule.Create(RuleAction.Block, TrafficDirection.Inbound, NetProtocol.Tcp, "65001", null, null, out _)!);
        engine.SetServiceRule(NoSuchService, RuleAction.Block, TrafficDirection.Outbound);
        var exported = RuleBackup.Export(engine, null, DateTime.UtcNow);
        Assert.Equal(3, exported.Count);

        engine.RemoveAllFilters();
        var plan = RuleBackup.Apply(engine, exported, ImportMode.Merge, null, applyMode: false, DateTime.UtcNow);

        Assert.Equal(3, plan.Add);
        Assert.Equal(RuleBackup.Fingerprint(exported), RuleBackup.Fingerprint(RuleBackup.Export(engine, null, DateTime.UtcNow)));

        // Importing the same file again changes nothing; Replace with an empty file removes everything.
        Assert.Equal(0, RuleBackup.Apply(engine, exported, ImportMode.Merge, null, false, DateTime.UtcNow).Total);
        var emptied = RuleBackup.Apply(engine, new RuleSet { AutoRules = exported.AutoRules }, ImportMode.Replace, null, false, DateTime.UtcNow);
        Assert.Equal(3, emptied.Remove);
        Assert.Equal(0, RuleBackup.Export(engine, null, DateTime.UtcNow).Count);
    }

    private WfpEngine Engine()
    {
        Assert.SkipUnless(Environment.GetEnvironmentVariable("CRIOFIRE_INTEGRATION") == "1",
            "Set CRIOFIRE_INTEGRATION=1 to run tests that change the firewall.");
        using (var identity = WindowsIdentity.GetCurrent())
        {
            Assert.True(new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator), "Firewall tests need an administrator terminal.");
        }

        if (_engine is null)
        {
            _engine = WfpEngine.Open();
            _engine.Uninstall();
            _engine.Install();
        }

        return _engine;
    }
}
