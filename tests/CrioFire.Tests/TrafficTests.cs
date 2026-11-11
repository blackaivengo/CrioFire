using CrioFire.Core;

namespace CrioFire.Tests;

/// <summary>The Activity page's filtered, paged view of blocked and allowed traffic.</summary>
public class TrafficTests
{
    private static readonly DateTime Now = new(2026, 11, 11, 18, 0, 0, DateTimeKind.Utc);

    private static LoggedEvent Blocked(int minutesAgo, string app, string remote, string kind = "DefaultBlock", string dir = "out", ulong filter = 5, string local = "192.168.1.10:50000") =>
        new(Now.AddMinutes(-minutesAgo), app, "TCP", remote, dir, kind, Local: local, FilterId: filter);

    private static LoggedEvent Allowed(int minutesAgo, string app, string remote, int port, string reason, int count = 1, string? service = null, string dir = "out") =>
        new(Now.AddMinutes(-minutesAgo), app, "TCP", remote, dir, null, Allowed: true, Count: count, Reason: reason, Service: service, Port: port);

    private static readonly LoggedEvent[] Events =
    [
        Blocked(1, @"C:\Apps\chat.exe", "203.0.113.5:443"),
        Blocked(2, @"C:\Apps\chat.exe", "203.0.113.5:443"),
        Blocked(3, @"C:\Apps\chat.exe", "203.0.113.6:443"),
        Blocked(4, @"C:\Apps\game.exe", "198.51.100.1:3478", kind: "AppRule", filter: 9),
        Blocked(90, @"C:\Apps\old.exe", "198.51.100.2:80", kind: "NetRule", filter: 12),
        Blocked(5, @"C:\Apps\server.exe", "203.0.113.9:51515", dir: "in", local: "192.168.1.10:8080"),
        Allowed(1, @"C:\Windows\System32\svchost.exe", "1.1.1.1", 53, "WindowsServices", count: 40, service: "Dnscache"),
        Allowed(2, @"C:\Apps\browser.exe", "203.0.113.7", 443, "Rule", count: 12),
        Allowed(3, @"C:\Apps\tool.exe", "127.0.0.1", 9000, "Loopback", count: 99),
        Allowed(200, @"C:\Apps\browser.exe", "203.0.113.7", 443, "Rule", count: 5),   // outside a 1-hour window
    ];

    private static TrafficPage Run(string kind = "all", string? search = null, string? why = null, string? dir = null, string? app = null,
        bool loopback = false, string? sort = null, int offset = 0, int limit = 100, int minutes = 60) =>
        TrafficQuery.Run(Events, new TrafficFilter(kind, Now.AddMinutes(-minutes), search, why, dir, app, null, loopback, sort, offset, limit));

    [Fact]
    public void BlockedConnectionsAreGroupedByProgramDestinationAndReason()
    {
        var page = Run("blocked");
        Assert.Equal(4, page.Total);                 // chat.exe x2 destinations, game.exe, server.exe (old.exe is too old)
        Assert.Equal(5, page.Connections);
        var chat = page.Items.Single(i => i.Remote == "203.0.113.5");
        Assert.Equal(2, chat.Count);
        Assert.Equal(443, chat.Port);
        Assert.Equal("No rule yet (mode)", chat.WhyLabel);
        Assert.Equal(Now.AddMinutes(-2), chat.FirstUtc);
        Assert.Equal(Now.AddMinutes(-1), chat.LastUtc);
        Assert.Equal(5ul, chat.FilterId);

        var inbound = page.Items.Single(i => i.Direction == "in");
        Assert.Equal(8080, inbound.Port);            // inbound: the local port names the service
        Assert.Equal("192.168.1.10:8080", inbound.Local);
    }

    [Fact]
    public void AllowedTrafficHidesLoopbackUnlessAsked()
    {
        Assert.Equal(2, Run("allowed").Total);
        Assert.Equal(3, Run("allowed", loopback: true).Total);
        Assert.Single(Run("allowed", why: "loopback").Items);   // asking for loopback shows it
        var dns = Run("allowed").Items.Single(i => i.Service == "Dnscache");
        Assert.Equal(40, dns.Count);
        Assert.Equal("Automatic: Windows services", dns.WhyLabel);
    }

    [Theory]
    [InlineData("mine", 2)]          // game.exe blocked by rule, browser.exe allowed by rule
    [InlineData("norule", 3)]        // chat.exe x2, server.exe
    [InlineData("automatic", 1)]     // svchost
    [InlineData("panic", 0)]
    public void ReasonGroups(string why, int expected) => Assert.Equal(expected, Run(why: why).Total);

    [Theory]
    [InlineData("chat", 2)]
    [InlineData("203.0.113.5", 1)]
    [InlineData("443", 3)]           // the port, also written :443
    [InlineData(":443", 3)]
    [InlineData("dnscache", 1)]
    [InlineData("chat 203.0.113.6", 1)]   // every word must match
    [InlineData("nothing-like-this", 0)]
    public void SearchMatchesEveryWord(string search, int expected) => Assert.Equal(expected, Run(search: search).Total);

    [Fact]
    public void FiltersByDirectionAndProgram()
    {
        Assert.Single(Run(dir: "in").Items);
        Assert.Equal(2, Run(app: @"c:\apps\CHAT.exe").Total);
    }

    [Fact]
    public void PagesAndSorts()
    {
        var all = Run(minutes: 600, loopback: true);
        Assert.Equal(8, all.Total);                  // browser.exe's two entries are one row
        var first = Run(minutes: 600, loopback: true, limit: 4);
        Assert.Equal(4, first.Items.Count);
        Assert.Equal(all.Items.Take(4), first.Items);
        var last = Run(minutes: 600, loopback: true, limit: 3, offset: 6);
        Assert.Equal(2, last.Items.Count);
        Assert.Equal(6, Run(minutes: 600, loopback: true, limit: 3, offset: 999).Offset);   // past the end: the last page

        var byCount = Run(minutes: 600, loopback: true, sort: "count");
        Assert.Equal(99, byCount.Items[0].Count);
        Assert.Equal(all.Items[0].LastUtc, all.Items.Max(i => i.LastUtc));
    }

    [Theory]
    [InlineData(443, "HTTPS (web)")]
    [InlineData(53, "DNS (name lookups)")]
    [InlineData(3389, "Remote Desktop")]
    [InlineData(40000, null)]
    public void PortNames(int port, string? expected) => Assert.Equal(expected, NetworkFacts.PortName(port));

    [Theory]
    [InlineData("127.0.0.1", "this PC (loopback)")]
    [InlineData("::1", "this PC (loopback)")]
    [InlineData("192.168.1.20", "local network (private)")]
    [InlineData("172.20.0.1", "local network (private)")]
    [InlineData("172.40.0.1", "internet")]
    [InlineData("169.254.3.4", "link-local (this network segment)")]
    [InlineData("239.255.255.250", "multicast (local discovery)")]
    [InlineData("fe80::1", "link-local (this network segment)")]
    [InlineData("fd00::5", "local network (private)")]
    [InlineData("2606:4700::1111", "internet")]
    [InlineData("not an address", "unknown")]
    public void AddressScopes(string address, string expected) => Assert.Equal(expected, NetworkFacts.AddressScope(address));

    [Fact]
    public void TheTrafficApiReadsBothLogsWithoutTheEngine()
    {
        var dir = Path.Combine(Path.GetTempPath(), $"criofire-traffic-{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        try
        {
            var blocked = new TrafficLog(Path.Combine(dir, "blocked.log"));
            var allowed = new TrafficLog(Path.Combine(dir, "allowed.log"));
            var now = DateTime.UtcNow;
            blocked.AppendLines([$$"""{"time":"{{now:O}}","app":"C:\\Apps\\a.exe","protocol":"TCP","local":"10.0.0.2:5000","remote":"1.2.3.4:443","direction":"out","filterId":7,"criofire":true,"kind":"DefaultBlock"}"""]);
            allowed.AppendSummaries([new AllowedSummary(now, @"C:\Apps\b.exe", null, "TCP", "out", "5.6.7.8", 443, "Rule", 3)]);
            var handler = new CrioFire.Core.Api.ApiHandler(null!, null, blocked, allowed);

            var all = handler.Handle(new CrioFire.Core.Api.ApiRequest { Op = CrioFire.Core.Api.ApiOps.Traffic, TrafficKind = "all", Minutes = 10 }, canWrite: false);
            Assert.True(all.Ok, all.Error);
            Assert.Equal(2, all.Traffic!.Total);
            Assert.Equal(4, all.Traffic.Connections);

            var onlyBlocked = handler.Handle(new CrioFire.Core.Api.ApiRequest { Op = CrioFire.Core.Api.ApiOps.Traffic, TrafficKind = "blocked", Minutes = 10 }, canWrite: false);
            Assert.Equal(@"C:\Apps\a.exe", Assert.Single(onlyBlocked.Traffic!.Items).App);

            Assert.False(handler.Handle(new CrioFire.Core.Api.ApiRequest { Op = CrioFire.Core.Api.ApiOps.Traffic, TrafficKind = "both" }, canWrite: false).Ok);
            Assert.False(handler.Handle(new CrioFire.Core.Api.ApiRequest { Op = CrioFire.Core.Api.ApiOps.Traffic, Why = "whatever" }, canWrite: false).Ok);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void BlockedLogLinesKeepTheLocalEndpointAndFilter()
    {
        var e = TrafficHistory.Parse("""{"time":"2026-11-11T18:00:00Z","app":"a.exe","protocol":"TCP","local":"10.0.0.2:5000","remote":"1.2.3.4:443","direction":"out","filterId":77,"criofire":true,"kind":"AppRule"}""")!;
        Assert.Equal("10.0.0.2:5000", e.Local);
        Assert.Equal(77ul, e.FilterId);
        Assert.Equal("AppRule", e.Kind);
    }
}
