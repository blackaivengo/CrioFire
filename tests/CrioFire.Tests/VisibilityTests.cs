using System.Net;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using CrioFire.Cli;
using CrioFire.Core;
using CrioFire.Core.Interop;

namespace CrioFire.Tests;

/// <summary>Allowed traffic, automatic rules, service rules and kernel rules: everything an administrator can see and control.</summary>
public class VisibilityTests
{
    private static readonly DateTime T0 = new(2026, 11, 10, 16, 5, 12, DateTimeKind.Utc);

    private static AllowedConnection Allowed(
        DateTime time,
        string? app = @"C:\Windows\System32\svchost.exe",
        CrioFireFilter? rule = null,
        bool loopback = false,
        TrafficDirection direction = TrafficDirection.Outbound,
        string remote = "203.0.113.5",
        int remotePort = 443,
        int localPort = 50000) =>
        new(time, app, ProtocolType.Tcp, new IPEndPoint(IPAddress.Parse("192.168.1.10"), localPort), new IPEndPoint(IPAddress.Parse(remote), remotePort), direction, loopback, 7, rule);

    private static CrioFireFilter Filter(FilterKind kind, string? builtIn = null) =>
        new(1, "x", FilterLayers.ConnectV4, null, kind, BuiltIn: builtIn);

    // ---- service SIDs and service rules ----

    [Fact]
    public void ServiceSidMatchesWhatScShowsidPrints()
    {
        Assert.Equal("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464", ServiceSid.For("TrustedInstaller"));
        Assert.Equal(ServiceSid.For("TrustedInstaller"), ServiceSid.For("trustedinstaller"));   // case-insensitive
        Assert.Equal("D:(A;;CC;;;S-1-5-80-1)", ServiceSid.Sddl("S-1-5-80-1"));
    }

    [Fact]
    public void ServiceRuleRoundTrips()
    {
        var rule = new ServiceRule(RuleAction.Block, TrafficDirection.Both, "DiagTrack");
        Assert.Equal("criofire:v1|svc|block|both|DiagTrack", rule.Format());
        Assert.True(ServiceRule.TryParse(rule.Format(), out var parsed));
        Assert.Equal(rule, parsed);
        Assert.Equal((FilterKind.ServiceRule, (FirewallMode?)null), FilterDescriptions.Classify(rule.Format()));
        Assert.False(RuleDescription.TryParse(rule.Format(), out _));   // never mistaken for a program rule
    }

    [Theory]
    [InlineData("")]
    [InlineData(" Dnscache")]
    [InlineData("a|b")]
    [InlineData("a\\b")]
    [InlineData("a)b")]
    public void BadServiceNamesAreRefused(string name)
    {
        Assert.False(ServiceRule.IsValidName(name));
        Assert.False(ServiceRule.TryParse($"criofire:v1|svc|block|out|{name}", out _));
    }

    [Fact]
    public void BuiltInNameIsReadFromTheDescription()
    {
        Assert.Equal("system", FilterDescriptions.BuiltInName(FilterDescriptions.BuiltInAllow("system")));
        Assert.Null(FilterDescriptions.BuiltInName("criofire:v1|default|ask"));
    }

    // ---- the kernel and svchost ----

    [Fact]
    public void KernelIsAProgramWithoutAPath()
    {
        Assert.True(KnownApps.IsKernel("system"));
        Assert.Equal("System", KnownApps.Normalize(" SYSTEM "));
        Assert.Equal(Path.GetFullPath("tool.exe"), KnownApps.Normalize("tool.exe"));
        Assert.Equal("Windows kernel (System)", KnownApps.DisplayName("System"));
        Assert.Equal("app.exe", KnownApps.DisplayName(@"C:\Apps\app.exe"));
    }

    [Theory]
    [InlineData(@"C:\Windows\System32\svchost.exe", true)]
    [InlineData(@"c:\windows\syswow64\SVCHOST.EXE", true)]
    [InlineData("svchost.exe", true)]
    [InlineData(@"C:\Apps\notsvchost.exe", false)]
    [InlineData(null, false)]
    public void ServiceHostIsRecognized(string? app, bool expected) => Assert.Equal(expected, KnownApps.IsServiceHost(app));

    // ---- automatic rules ----

    [Fact]
    public void AutoRulePolicyIsOnByDefaultAndRemembersOff()
    {
        var policy = AutoRulePolicy.Parse("# comment\nsvchost=off\nbogus=off\nsystem=on\n");
        Assert.False(policy.IsEnabled(AutoRulePolicy.WindowsServices));
        Assert.True(policy.IsEnabled(AutoRulePolicy.WindowsKernel));
        Assert.True(new AutoRulePolicy().IsEnabled(AutoRulePolicy.WindowsServices));

        var again = AutoRulePolicy.Parse(policy.Format());
        Assert.False(again.IsEnabled("SVCHOST"));
        again.Set("svchost", true);
        Assert.True(again.IsEnabled("svchost"));
        Assert.Throws<ArgumentException>(() => again.Set("explorer", false));
    }

    [Fact]
    public void AutoRulePolicySavesAndLoads()
    {
        var path = Path.Combine(Path.GetTempPath(), $"criofire-auto-{Guid.NewGuid():N}", "auto-rules.txt");
        try
        {
            Assert.True(AutoRulePolicy.Load(path).IsEnabled("system"));   // missing file: everything on
            var policy = new AutoRulePolicy();
            policy.Set("system", false);
            policy.Save(path);
            Assert.False(AutoRulePolicy.Load(path).IsEnabled("system"));
        }
        finally
        {
            Directory.Delete(Path.GetDirectoryName(path)!, recursive: true);
        }
    }

    // ---- why a connection was allowed ----

    [Fact]
    public void AllowReasonsComeFromTheFilter()
    {
        Assert.Equal(AllowReason.Rule, AllowReasons.Classify(Filter(FilterKind.AppRule), false));
        Assert.Equal(AllowReason.NetRule, AllowReasons.Classify(Filter(FilterKind.NetRule), false));
        Assert.Equal(AllowReason.ServiceRule, AllowReasons.Classify(Filter(FilterKind.ServiceRule), false));
        Assert.Equal(AllowReason.WindowsServices, AllowReasons.Classify(Filter(FilterKind.BuiltInAllow, "svchost"), false));
        Assert.Equal(AllowReason.WindowsKernel, AllowReasons.Classify(Filter(FilterKind.BuiltInAllow, "system"), false));
        Assert.Equal(AllowReason.Loopback, AllowReasons.Classify(null, true));
        Assert.Equal(AllowReason.NoRule, AllowReasons.Classify(null, false));

        Assert.True(AllowReasons.IsAutomatic(AllowReason.WindowsServices));
        Assert.True(AllowReasons.IsAutomatic(nameof(AllowReason.NoRule)));
        Assert.False(AllowReasons.IsAutomatic(AllowReason.Rule));
        Assert.Equal("No rule: Windows Firewall decides", AllowReasons.Label("NoRule", "in"));
        Assert.Equal("No rule: Learning mode", AllowReasons.Label("NoRule", "out"));
    }

    [Fact]
    public void TheAllowingFilterIsFoundEvenWhenAnotherFirewallMadeTheFinalCall()
    {
        const string app = @"C:\Apps\chat.exe";
        var appRule = new CrioFireFilter(10, "a", FilterLayers.ConnectV4, new RuleDescription(RuleAction.Allow, TrafficDirection.Outbound, app));
        var inboundRule = new CrioFireFilter(11, "b", FilterLayers.RecvAcceptV4, new RuleDescription(RuleAction.Allow, TrafficDirection.Inbound, app));
        var netRule = new CrioFireFilter(12, "c", FilterLayers.ConnectV4, null, FilterKind.NetRule,
            Net: new NetRule(RuleAction.Allow, TrafficDirection.Outbound, NetProtocol.Tcp, "443", "203.0.113.0/24", app));
        var services = new CrioFireFilter(13, "d", FilterLayers.ConnectV4, null, FilterKind.BuiltInAllow, BuiltIn: "svchost");
        var serviceRule = new CrioFireFilter(14, "e", FilterLayers.ConnectV4, null, FilterKind.ServiceRule, Service: new ServiceRule(RuleAction.Allow, TrafficDirection.Outbound, "BITS"));
        var block = new CrioFireFilter(15, "f", FilterLayers.ConnectV4, new RuleDescription(RuleAction.Block, TrafficDirection.Outbound, @"C:\Apps\bad.exe"));
        var filters = new[] { appRule, inboundRule, netRule, services, serviceRule, block };

        // Event names a Windows Firewall filter (7): CrioFire's own matching decides.
        Assert.Equal(netRule, AllowReasons.Resolve(filters, Allowed(T0, app: app)));                    // port + address + app beats the app rule
        Assert.Equal(appRule, AllowReasons.Resolve(filters, Allowed(T0, app: app, remotePort: 80)));
        Assert.Null(AllowReasons.Resolve(filters, Allowed(T0, app: @"C:\Apps\other.exe")));
        Assert.Equal(services, AllowReasons.Resolve(filters, Allowed(T0)));
        Assert.Equal(serviceRule, AllowReasons.Resolve(filters, Allowed(T0) with { Service = "BITS, wuauserv" }));
        Assert.Null(AllowReasons.Resolve(filters, Allowed(T0, app: @"C:\Apps\bad.exe")));               // block rules never explain an allow
        Assert.Equal(inboundRule, AllowReasons.Resolve(filters, Allowed(T0, app: app, direction: TrafficDirection.Inbound)));

        // An event that names one of CrioFire's own allow filters is trusted as it is.
        Assert.Equal(appRule, AllowReasons.Resolve(filters, Allowed(T0, app: @"C:\Apps\other.exe") with { FilterId = 10 }));
    }

    [Fact]
    public void LoopbackIsRecognizedWithoutTheEventFlag()
    {
        var local = new IPEndPoint(IPAddress.Parse("192.168.1.10"), 50000);
        Assert.True(AllowReasons.IsLoopback(false, local, new IPEndPoint(IPAddress.Loopback, 80)));
        Assert.True(AllowReasons.IsLoopback(false, local, new IPEndPoint(IPAddress.IPv6Loopback, 80)));
        Assert.True(AllowReasons.IsLoopback(false, local, new IPEndPoint(IPAddress.Parse("192.168.1.10"), 80)));   // its own address
        Assert.False(AllowReasons.IsLoopback(false, local, new IPEndPoint(IPAddress.Parse("203.0.113.5"), 80)));
        Assert.True(AllowReasons.IsLoopback(true, null, null));
    }

    [Fact]
    public void AllowedConnectionsAreSummedPerMinute()
    {
        var summaries = AllowedSummary.Aggregate(
        [
            Allowed(T0),
            Allowed(T0.AddSeconds(30), localPort: 50001),           // same minute, same destination
            Allowed(T0.AddSeconds(50)),                              // next minute
            Allowed(T0, rule: Filter(FilterKind.BuiltInAllow, "svchost")),
            Allowed(T0, direction: TrafficDirection.Inbound, remotePort: 51515, localPort: 3389),
        ]);

        Assert.Equal(4, summaries.Count);
        var first = summaries.First(s => s.Reason == "NoRule" && s.Direction == "out" && s.MinuteUtc.Minute == 5);
        Assert.Equal(2, first.Count);
        Assert.Equal(new DateTime(2026, 11, 10, 16, 5, 0, DateTimeKind.Utc), first.MinuteUtc);
        Assert.Equal(443, first.Port);
        Assert.Equal("203.0.113.5", first.Remote);

        var inbound = summaries.Single(s => s.Direction == "in");
        Assert.Equal(3389, inbound.Port);   // inbound: the local port names the service
    }

    [Fact]
    public void AllowedLogLinesReadBack()
    {
        var line = new AllowedSummary(T0, @"C:\Windows\System32\svchost.exe", "Dnscache", "UDP", "out", "1.1.1.1", 53, "WindowsServices", 12).ToJsonLine();
        var e = TrafficHistory.Parse(line)!;
        Assert.True(e.Allowed);
        Assert.Equal(12, e.Count);
        Assert.Equal("Dnscache", e.Service);
        Assert.Equal(53, e.Port);
        Assert.Equal("1.1.1.1", e.Remote);
        Assert.Equal("WindowsServices", e.Reason);
        Assert.False(e.ByMode);

        var blocked = TrafficHistory.Parse("""{"time":"2026-11-10T16:05:12Z","app":"a.exe","kind":"DefaultBlock"}""")!;
        Assert.False(blocked.Allowed);
        Assert.Equal(1, blocked.Count);
    }

    [Fact]
    public void AllowedGroupsSumAndHideLoopbackWhenAsked()
    {
        LoggedEvent Ev(int minute, string reason, int count, string remote = "1.1.1.1") =>
            new(T0.AddMinutes(minute), "svchost.exe", "UDP", remote, "out", null, Allowed: true, Count: count, Reason: reason, Port: 53);

        var events = new[] { Ev(0, "WindowsServices", 3), Ev(2, "WindowsServices", 4), Ev(1, "Loopback", 9, "127.0.0.1"), Ev(1, "NoRule", 1, "8.8.8.8") };
        var all = AllowedGroup.From(events);
        Assert.Equal(3, all.Count);
        var dns = all.Single(g => g.Remote == "1.1.1.1");
        Assert.Equal(7, dns.Count);
        Assert.Equal(T0, dns.FirstUtc);
        Assert.Equal(T0.AddMinutes(2), dns.LastUtc);
        Assert.Equal(dns, all[0]);   // newest first

        Assert.DoesNotContain(AllowedGroup.From(events, includeLoopback: false), g => g.Reason == "Loopback");
    }

    [Fact]
    public void RecentEventsDropsAllowedConnectionsAlreadySeen()
    {
        var recent = new RecentEvents(TimeSpan.FromSeconds(10));
        var a = Allowed(T0);
        Assert.Single(recent.KeepNew([a], T0));
        Assert.Empty(recent.KeepNew([a], T0.AddSeconds(2)));
        Assert.Single(recent.KeepNew([a with { Direction = TrafficDirection.Inbound }], T0.AddSeconds(2)));
    }

    // ---- reports ----

    [Fact]
    public void ReportsCountAllowedTrafficSeparately()
    {
        var now = new DateTime(2026, 11, 10, 16, 30, 0, DateTimeKind.Utc);
        LoggedEvent A(int hoursAgo, string reason, int count, string app = "svchost.exe", string? service = null, string dir = "out") =>
            new(now.AddHours(-hoursAgo), app, "TCP", "203.0.113.9", dir, null, Allowed: true, Count: count, Reason: reason, Service: service, Port: 443);

        var events = new[]
        {
            A(1, "WindowsServices", 5, service: "wuauserv"),
            A(2, "WindowsServices", 2, service: "Dnscache"),
            A(1, "Rule", 10, app: @"C:\Apps\chat.exe"),
            A(3, "NoRule", 1, app: @"C:\Apps\chat.exe", dir: "in"),
            A(30, "Rule", 100, app: @"C:\Apps\chat.exe"),   // the day before: comparison only
            new LoggedEvent(now.AddHours(-1), @"C:\Apps\bad.exe", "TCP", "198.51.100.1:80", "out", "DefaultBlock"),
        };

        var r = ReportBuilder.Build(events, ReportBuilder.Day, now, TimeZoneInfo.Utc);
        Assert.Equal(1, r.Total);                 // blocked count unchanged by allowed traffic
        Assert.Equal(18, r.AllowedTotal);
        Assert.Equal(8, r.AllowedAutomatic);      // services 7 + no rule 1
        Assert.Equal(100, r.AllowedPrevious);
        Assert.Equal(3, r.AllowedProgramCount);   // chat.exe, svchost/wuauserv, svchost/Dnscache
        Assert.Equal(18, r.Buckets.Sum(b => b.Allowed));

        var chat = r.TopAllowedPrograms!.First();
        Assert.Equal(@"C:\Apps\chat.exe", chat.App);
        Assert.Equal(11, chat.Count);
        Assert.Equal(1, chat.Automatic);
        Assert.Equal("Rule", chat.Reason);
        Assert.Equal("both", chat.Direction);
        Assert.Contains(r.TopAllowedPrograms!, p => p.Service == "wuauserv" && p.Count == 5);
        Assert.Equal("Rule", r.AllowedReasons![0].Reason);

        var csv = ReportBuilder.ToCsv(r, TimeZoneInfo.Utc);
        Assert.Contains("Allowed,18", csv);
        Assert.Contains("Allowed program,Service,Direction", csv);
        Assert.Contains("svchost.exe,wuauserv,out,5,5,Automatic: Windows services", csv);
    }

    // ---- which service owns a socket ----

    [Fact]
    public void ServiceIsFoundFromTheConnectionTable()
    {
        var local = new IPEndPoint(IPAddress.Parse("192.168.1.10"), 50000);
        var remote = new IPEndPoint(IPAddress.Parse("203.0.113.5"), 443);
        var table = new List<LiveConnection>
        {
            new(ProtocolType.Tcp, local, new IPEndPoint(IPAddress.Parse("203.0.113.6"), 443), "Established", 100, null),
            new(ProtocolType.Tcp, local, remote, "Established", 200, null),
            new(ProtocolType.Udp, new IPEndPoint(IPAddress.Any, 5353), null, "Bound", 300, null),
        };
        var services = new Dictionary<int, string[]> { [100] = ["Other"], [200] = ["BITS", "wuauserv"], [300] = ["Dnscache"] };

        Assert.Equal("BITS, wuauserv", ServiceAttribution.Find(table, services, ProtocolType.Tcp, local, remote));
        Assert.Equal("Dnscache", ServiceAttribution.Find(table, services, ProtocolType.Udp, new IPEndPoint(IPAddress.Parse("192.168.1.10"), 5353), null));
        Assert.Null(ServiceAttribution.Find(table, services, ProtocolType.Udp, new IPEndPoint(IPAddress.Any, 9999), null));
        Assert.Null(ServiceAttribution.Find(table, services, ProtocolType.Tcp, null, remote));
    }

    [Fact]
    public void ServicesAreGroupedByProcess()
    {
        var byPid = WindowsServiceList.ByProcess(
        [
            new WindowsService("wuauserv", "Windows Update", 200, true),
            new WindowsService("BITS", "Background Intelligent Transfer Service", 200, true),
            new WindowsService("Spooler", "Print Spooler", 0, false),
        ]);
        Assert.Equal(new[] { "BITS", "wuauserv" }, byPid[200]);
        Assert.False(byPid.ContainsKey(0));
    }

    // ---- command line ----

    [Fact]
    public void ServiceRulesFromTheCommandLine()
    {
        var block = CommandLine.Parse(["block", "--service", "DiagTrack", "--both"], out var error);
        Assert.Null(error);
        Assert.Equal(CommandKind.Block, block.Kind);
        Assert.Equal("DiagTrack", block.Service);
        Assert.Equal(TrafficDirection.Both, block.Direction);

        var unblock = CommandLine.Parse(["unblock", "--service", "DiagTrack"], out error);
        Assert.Null(error);
        Assert.Equal(TrafficDirection.Both, unblock.Direction);

        CommandLine.Parse(["block", "--service", "DiagTrack", "--port", "80"], out error);
        Assert.NotNull(error);
        CommandLine.Parse(["block", "--service"], out error);
        Assert.NotNull(error);
    }

    [Fact]
    public void AllowedAndAutoCommands()
    {
        var allowed = CommandLine.Parse(["allowed", "--minutes", "120", "--local"], out var error);
        Assert.Null(error);
        Assert.Equal(CommandKind.Allowed, allowed.Kind);
        Assert.Equal(120, allowed.Minutes);
        Assert.True(allowed.All);
        Assert.Equal(60, CommandLine.Parse(["allowed"], out _).Minutes);

        Assert.Equal(CommandKind.AutoShow, CommandLine.Parse(["auto"], out _).Kind);
        var off = CommandLine.Parse(["auto", "SVCHOST", "off"], out error);
        Assert.Null(error);
        Assert.Equal(CommandKind.AutoSet, off.Kind);
        Assert.Equal("svchost", off.AutoRule);
        Assert.False(off.Enabled);
        CommandLine.Parse(["auto", "explorer", "off"], out error);
        Assert.NotNull(error);
    }

    // ---- struct layouts for the allowed-event and service APIs ----

    [Fact]
    public void AllowedEventStructsMatchWindowsSdk()
    {
        Assert.Equal(88, Unsafe.SizeOf<FWPM_NET_EVENT_HEADER0>());
        Assert.Equal(104, Unsafe.SizeOf<FWPM_NET_EVENT_HEADER2>());
        Assert.Equal(120, Unsafe.SizeOf<FWPM_NET_EVENT2>());
        Assert.Equal(32, Unsafe.SizeOf<FWPM_NET_EVENT_CLASSIFY_ALLOW0>());
        Assert.Equal(56, Unsafe.SizeOf<ENUM_SERVICE_STATUS_PROCESSW>());
    }
}
