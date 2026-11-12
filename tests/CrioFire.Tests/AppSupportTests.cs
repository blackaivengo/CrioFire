using System.Net;
using System.Runtime.CompilerServices;
using CrioFire.Cli;
using CrioFire.Core;
using CrioFire.Core.Api;

namespace CrioFire.Tests;

public class AlertTrackerTests
{
    private static readonly DateTime T0 = new(2026, 11, 9, 10, 0, 0, DateTimeKind.Utc);

    private static EventInfo Blocked(string app, string kind = nameof(FilterKind.DefaultBlock), int second = 0) =>
        new(T0.AddSeconds(second), app, "TCP", null, "1.2.3.4:443", "out", true, 7, kind);

    private static RuleInfo Rule(string app) =>
        new(1, nameof(FilterKind.AppRule), "allow", "out", app, "outbound IPv4", "CrioFire: allow");

    [Fact]
    public void AsksOnceAboutAProgramStoppedByTheCatchAllBlock()
    {
        var tracker = new AlertTracker();
        var events = new[] { Blocked(@"C:\a.exe"), Blocked(@"C:\a.exe", second: 1), Blocked(@"C:\A.EXE", second: 2) };

        var first = tracker.NewAlerts(events, []);
        Assert.Single(first);
        Assert.Equal(@"C:\a.exe", first[0].App);

        Assert.Empty(tracker.NewAlerts(events, []));   // still pending
    }

    [Fact]
    public void IgnoresProgramsWithRulesAndBlocksByTheUsersOwnRules()
    {
        var tracker = new AlertTracker();
        var events = new[]
        {
            Blocked(@"C:\ruled.exe"),
            Blocked(@"C:\blocked-by-rule.exe", nameof(FilterKind.AppRule)),
            new EventInfo(T0, null, "UDP", null, null, "out", true, 7, nameof(FilterKind.DefaultBlock)),
        };

        Assert.Empty(tracker.NewAlerts(events, [Rule(@"C:\RULED.exe")]));
    }

    [Fact]
    public void DismissedProgramsAreNotAskedAgainButDecidedOnesCanBe()
    {
        var tracker = new AlertTracker();
        Assert.Equal(2, tracker.NewAlerts([Blocked(@"C:\a.exe"), Blocked(@"C:\b.exe")], []).Count);

        tracker.Dismissed(@"C:\a.exe");
        tracker.Decided(@"C:\b.exe");

        var again = tracker.NewAlerts([Blocked(@"C:\a.exe", second: 5), Blocked(@"C:\b.exe", second: 5)], []);
        Assert.Equal(@"C:\b.exe", Assert.Single(again).App);   // b's rule was removed later, so ask again
    }
}

public sealed class TemporaryRuleStoreTests : IDisposable
{
    private static readonly string[] ExpiredApps = [@"C:\exact.exe", @"C:\old.exe"];

    private static readonly DateTime Now = new(2026, 11, 9, 10, 0, 0, DateTimeKind.Utc);
    private readonly string _dir = Path.Combine(Path.GetTempPath(), $"criofire-tests-{Guid.NewGuid():N}");

    public void Dispose()
    {
        if (Directory.Exists(_dir))
        {
            Directory.Delete(_dir, recursive: true);
        }
    }

    private TemporaryRuleStore NewStore() => new(Path.Combine(_dir, "sub", "temporary-rules.json"));

    [Fact]
    public void StartsEmptyAndSurvivesANewInstance()
    {
        var store = NewStore();
        Assert.Empty(store.All());

        store.Add(new TemporaryRule(@"C:\a.exe", "out", Now.AddMinutes(60)));
        Assert.Equal(new TemporaryRule(@"C:\a.exe", "out", Now.AddMinutes(60)), Assert.Single(NewStore().All()));
    }

    [Fact]
    public void AddReplacesTheSameProgramAndDirection()
    {
        var store = NewStore();
        store.Add(new TemporaryRule(@"C:\a.exe", "out", Now.AddMinutes(10)));
        store.Add(new TemporaryRule(@"C:\A.exe", "out", Now.AddMinutes(60)));
        store.Add(new TemporaryRule(@"C:\a.exe", "in", Now.AddMinutes(5)));

        var all = store.All();
        Assert.Equal(2, all.Count);
        Assert.Contains(all, r => r.Direction == "out" && r.ExpiresUtc == Now.AddMinutes(60));
    }

    [Fact]
    public void TakeExpiredRemovesOnlyDueRules()
    {
        var store = NewStore();
        store.Add(new TemporaryRule(@"C:\old.exe", "out", Now.AddMinutes(-1)));
        store.Add(new TemporaryRule(@"C:\exact.exe", "out", Now));
        store.Add(new TemporaryRule(@"C:\later.exe", "out", Now.AddMinutes(1)));

        var expired = store.TakeExpired(Now);
        Assert.Equal(ExpiredApps, expired.Select(r => r.App).Order().ToArray());
        Assert.Equal(@"C:\later.exe", Assert.Single(store.All()).App);
        Assert.Empty(store.TakeExpired(Now));
    }

    [Fact]
    public void RemoveAndClear()
    {
        var store = NewStore();
        store.Add(new TemporaryRule(@"C:\a.exe", "out", Now));
        store.Add(new TemporaryRule(@"C:\a.exe", "in", Now));
        store.Add(new TemporaryRule(@"C:\b.exe", "out", Now));

        store.Remove(@"C:\A.EXE");
        Assert.Equal(@"C:\b.exe", Assert.Single(store.All()).App);

        store.Clear();
        Assert.Empty(store.All());
        store.Clear();   // nothing to delete is fine
    }

    [Fact]
    public void ACorruptFileIsTreatedAsEmpty()
    {
        var store = NewStore();
        Directory.CreateDirectory(Path.GetDirectoryName(store.FilePath)!);
        File.WriteAllText(store.FilePath, "{ not json");
        Assert.Empty(store.All());

        store.Add(new TemporaryRule(@"C:\a.exe", "out", Now));
        Assert.Single(store.All());
    }
}

public class ConnectionTableTests
{
    [Theory]
    [InlineData(0x5000u, 80)]        // bytes 00 50 in memory -> port 0x0050
    [InlineData(0xBB01u, 443)]       // bytes 01 BB -> 0x01BB
    [InlineData(0xFFFFu, 65535)]
    [InlineData(0x0000u, 0)]
    [InlineData(0xABCD5000u, 80)]    // high 16 bits are ignored
    public void PortsAreInNetworkOrder(uint raw, int expected) =>
        Assert.Equal(expected, ConnectionTable.PortFromNetworkOrder(raw));

    [Fact]
    public void AddressesAreInNetworkOrder()
    {
        Assert.Equal(IPAddress.Parse("127.0.0.1"), ConnectionTable.AddressFromNetworkOrder(0x0100007Fu));
        Assert.Equal(IPAddress.Parse("192.168.1.20"), ConnectionTable.AddressFromNetworkOrder(0x1401A8C0u));
    }

    [Theory]
    [InlineData(2u, "Listening")]
    [InlineData(5u, "Established")]
    [InlineData(11u, "TimeWait")]
    [InlineData(99u, "State99")]
    public void TcpStates(uint state, string expected) => Assert.Equal(expected, ConnectionTable.TcpStateName(state));

    [Fact]
    public void RowStructSizesMatchWindowsSdk()
    {
        Assert.Equal(24, Unsafe.SizeOf<MIB_TCPROW_OWNER_PID>());
        Assert.Equal(56, Unsafe.SizeOf<MIB_TCP6ROW_OWNER_PID>());
        Assert.Equal(12, Unsafe.SizeOf<MIB_UDPROW_OWNER_PID>());
        Assert.Equal(28, Unsafe.SizeOf<MIB_UDP6ROW_OWNER_PID>());
    }
}

public class TemporaryRuleCommandTests
{
    [Fact]
    public void AllowForMinutes()
    {
        var command = CommandLine.Parse(["allow", @"C:\a.exe", "--for", "60"], out var error);
        Assert.Null(error);
        Assert.Equal(new Command(CommandKind.Allow, @"C:\a.exe", TrafficDirection.Outbound, ExpiresMinutes: 60), command);
    }

    [Fact]
    public void BlockForMinutesWithDirection()
    {
        var command = CommandLine.Parse(["block", "--both", "--for", "5", @"C:\a.exe"], out var error);
        Assert.Null(error);
        Assert.Equal(5, command.ExpiresMinutes);
        Assert.Equal(TrafficDirection.Both, command.Direction);
    }

    [Theory]
    [InlineData("0")]
    [InlineData("10081")]
    [InlineData("soon")]
    public void BadMinutesAreRejected(string minutes)
    {
        CommandLine.Parse(["allow", @"C:\a.exe", "--for", minutes], out var error);
        Assert.NotNull(error);
    }

    [Fact]
    public void ForWithoutANumberIsRejected()
    {
        CommandLine.Parse(["allow", @"C:\a.exe", "--for"], out var error);
        Assert.NotNull(error);
    }

    [Fact]
    public void UnblockHasNoFor()
    {
        CommandLine.Parse(["unblock", @"C:\a.exe", "--for", "5"], out var error);
        Assert.NotNull(error);
    }

    [Fact]
    public void ExpiryAndKindRoundTripThroughJson()
    {
        var expires = new DateTime(2026, 11, 9, 11, 0, 0, DateTimeKind.Utc);
        var response = new ApiResponse
        {
            Ok = true,
            Rules = [new RuleInfo(1, "AppRule", "allow", "out", @"C:\a.exe", "outbound IPv4", "n", expires)],
            Events = [new EventInfo(expires, @"C:\a.exe", "TCP", null, null, "out", true, 9, "DefaultBlock")],
        };

        var back = ApiJson.DeserializeResponse(ApiJson.Serialize(response))!;
        Assert.Equal(expires, back.Rules![0].ExpiresUtc);
        Assert.Equal("DefaultBlock", back.Events![0].Kind);

        var request = ApiJson.DeserializeRequest(ApiJson.Serialize(new ApiRequest { Op = ApiOps.SetRule, App = @"C:\a.exe", Action = "allow", ExpiresMinutes = 60 }))!;
        Assert.Equal(60, request.ExpiresMinutes);
    }
}
