using System.Globalization;
using CrioFire.Cli;
using CrioFire.Core;
using CrioFire.Core.Api;

namespace CrioFire.Tests;

/// <summary>Data used per program: reading Windows' events, summing, the per-day file, the API and the command line.</summary>
public sealed class DataUsageTests : IDisposable
{
    private const string Browser = @"C:\Apps\browser.exe";
    private const string Chat = @"C:\Apps\chat.exe";
    private static readonly DateOnly Day = new(2026, 11, 13);

    private readonly string _dir = Path.Combine(Path.GetTempPath(), "criofire-usage-" + Guid.NewGuid().ToString("N"));

    public void Dispose()
    {
        if (Directory.Exists(_dir))
        {
            Directory.Delete(_dir, recursive: true);
        }
    }

    [Theory]
    [InlineData(10, true)]    // TCP over IPv4, sent
    [InlineData(11, false)]   // TCP over IPv4, received
    [InlineData(42, true)]    // UDP over IPv4, sent
    [InlineData(43, false)]   // UDP over IPv4, received
    public void IPv4SendsAndReceivesAreRead(ushort id, bool sent)
    {
        var parsed = NetworkUsageEvents.Parse(id, Event(1234, 1500, [203, 0, 113, 9], [192, 168, 1, 20]));

        Assert.True(parsed.HasValue);
        var transfer = parsed.GetValueOrDefault();
        Assert.Equal(1234u, transfer.ProcessId);
        Assert.Equal(1500u, transfer.Bytes);
        Assert.Equal(sent, transfer.Sent);
        Assert.False(transfer.Loopback);
    }

    [Theory]
    [InlineData(26, true)]
    [InlineData(27, false)]
    [InlineData(58, true)]
    [InlineData(59, false)]
    public void IPv6SendsAndReceivesAreRead(ushort id, bool sent)
    {
        var remote = System.Net.IPAddress.Parse("2001:db8::9").GetAddressBytes();
        var local = System.Net.IPAddress.Parse("2001:db8::20").GetAddressBytes();
        var parsed = NetworkUsageEvents.Parse(id, Event(77, 64_000, remote, local));

        Assert.True(parsed.HasValue);
        var transfer = parsed.GetValueOrDefault();
        Assert.Equal(77u, transfer.ProcessId);
        Assert.Equal(64_000u, transfer.Bytes);
        Assert.Equal(sent, transfer.Sent);
        Assert.False(transfer.Loopback);
    }

    [Fact]
    public void TrafficThatStaysOnThisPcIsMarked()
    {
        Assert.True(NetworkUsageEvents.Parse(10, Event(1, 10, [127, 0, 0, 1], [127, 0, 0, 1]))!.Value.Loopback);
        Assert.True(NetworkUsageEvents.Parse(11, Event(1, 10, [192, 168, 1, 20], [127, 0, 0, 1]))!.Value.Loopback);
        var loopback = System.Net.IPAddress.IPv6Loopback.GetAddressBytes();
        Assert.True(NetworkUsageEvents.Parse(26, Event(1, 10, loopback, loopback))!.Value.Loopback);
        Assert.False(NetworkUsageEvents.Parse(26, Event(1, 10, System.Net.IPAddress.Parse("::2").GetAddressBytes(), loopback.Select(_ => (byte)0).ToArray()))!.Value.Loopback);
    }

    [Fact]
    public void OtherEventsAndShortDataAreIgnored()
    {
        Assert.Null(NetworkUsageEvents.Parse(12, Event(1, 10, [203, 0, 113, 9], [192, 168, 1, 20])));   // TCP connect
        Assert.Null(NetworkUsageEvents.Parse(10, new byte[12]));
        Assert.Null(NetworkUsageEvents.Parse(26, new byte[30]));
        Assert.Null(NetworkUsageEvents.Parse(10, []));
    }

    [Fact]
    public void TheCounterSumsPerProgramAndStartsAgainAfterTake()
    {
        var counter = new DataCounter(pid => pid switch { 100 => Browser, 101 => Browser, 200 => Chat, _ => null });

        counter.Add(new NetworkTransfer(100, 1000, Sent: true, Loopback: false), 0);
        counter.Add(new NetworkTransfer(101, 500, Sent: false, Loopback: false), 0);   // a second browser process
        counter.Add(new NetworkTransfer(200, 40, Sent: false, Loopback: false), 0);
        counter.Add(new NetworkTransfer(200, 9999, Sent: false, Loopback: true), 0);   // not counted
        counter.Add(new NetworkTransfer(4, 300, Sent: true, Loopback: false), 0);
        counter.Add(new NetworkTransfer(999, 7, Sent: true, Loopback: false), 0);

        var counts = counter.Take().ToDictionary(a => a.App);
        Assert.Equal(new AppUsage(Browser, 1000, 500), counts[Browser]);
        Assert.Equal(new AppUsage(Chat, 0, 40), counts[Chat]);
        Assert.Equal(new AppUsage(KnownApps.Kernel, 300, 0), counts[KnownApps.Kernel]);
        Assert.Equal(new AppUsage(AppUsage.UnknownApp, 7, 0), counts[AppUsage.UnknownApp]);
        Assert.Empty(counter.Take());
    }

    [Fact]
    public void AProgramIsLookedUpOnceAMinuteAndKeepsItsNameAfterItEnds()
    {
        var lookups = 0;
        string? path = Browser;
        var counter = new DataCounter(_ =>
        {
            lookups++;
            return path;
        });

        counter.Add(new NetworkTransfer(100, 1, true, false), 0);
        counter.Add(new NetworkTransfer(100, 1, true, false), 30_000);
        Assert.Equal(1, lookups);

        path = null;   // the process ended
        counter.Add(new NetworkTransfer(100, 1, true, false), 61_000);
        Assert.Equal(2, lookups);
        Assert.Equal(Browser, Assert.Single(counter.Take()).App);

        path = Chat;   // Windows gave the id to another program
        counter.Add(new NetworkTransfer(100, 1, true, false), 130_000);
        Assert.Equal(Chat, Assert.Single(counter.Take()).App);
    }

    [Fact]
    public void DaysAddUpAndOldDaysAreDropped()
    {
        var days = DataUsageStore.Merge([], Day.AddDays(-40), [new AppUsage(Browser, 1, 1)]);
        days = DataUsageStore.Merge(days, Day.AddDays(-1), [new AppUsage(Browser, 100, 200)]);
        days = DataUsageStore.Merge(days, Day, [new AppUsage(Browser, 10, 20), new AppUsage(Chat, 5, 0)]);
        days = DataUsageStore.Merge(days, Day, [new AppUsage(@"c:\apps\BROWSER.exe", 1, 2)]);

        Assert.Equal(["2026-11-12", "2026-11-13"], days.Select(d => d.Day));
        var today = days[^1].Apps;
        Assert.Equal(Browser, today[0].App);
        Assert.Equal(11, today[0].Sent);
        Assert.Equal(22, today[0].Received);

        Assert.Equal(33, DataUsageStore.Totals(days, Day).Single(a => a.App == Browser).Total);
        var week = DataUsageStore.Totals(days, DataUsageStore.PeriodStart("7d", Day));
        Assert.Equal([Browser, Chat], week.Select(a => a.App));
        Assert.Equal(333, week[0].Total);
    }

    [Theory]
    [InlineData(null, "2026-11-13")]
    [InlineData("today", "2026-11-13")]
    [InlineData("7d", "2026-11-07")]
    [InlineData("30d", "2026-10-15")]
    public void PeriodsCountToday(string? period, string first) =>
        Assert.Equal(first, DataUsageStore.DayText(DataUsageStore.PeriodStart(period, Day)));

    [Fact]
    public void AnUnknownPeriodIsRefused() =>
        Assert.Throws<ArgumentException>(() => DataUsageStore.PeriodStart("forever", Day));

    [Fact]
    public void TheFileKeepsTheCountsAndAResetClearsThem()
    {
        var store = new DataUsageStore(Path.Combine(_dir, "data-usage.json"));
        Assert.Empty(store.Load());

        store.Save(DataUsageStore.Merge([], Day, [new AppUsage(Browser, 10, 20)]));
        Assert.Equal(30, store.Load().Single().Apps.Single().Total);

        store.RequestReset();
        Assert.True(store.ResetRequested);
        store.CompleteReset();
        Assert.False(store.ResetRequested);
        Assert.Empty(store.Load());

        File.WriteAllText(store.FilePath, "not json");
        Assert.Empty(store.Load());
    }

    [Fact]
    public void TheApiShowsThePeriodAndOnlyCrioFireMayClearIt()
    {
        var store = new DataUsageStore(Path.Combine(_dir, "data-usage.json"));
        var today = DateOnly.FromDateTime(DateTime.Now);
        var days = DataUsageStore.Merge([], today.AddDays(-3), [new AppUsage(Chat, 1000, 0)]);
        store.Save(DataUsageStore.Merge(days, today, [new AppUsage(Browser, 10, 20)]));
        var handler = new ApiHandler(null!, usage: store);

        var todayOnly = handler.Handle(new ApiRequest { Op = ApiOps.Usage }, ClientRights.ReadOnly).Usage!;
        Assert.Equal("today", todayOnly.Period);
        Assert.Equal(Browser, Assert.Single(todayOnly.Apps).App);
        Assert.Equal(10, todayOnly.Sent);
        Assert.Equal(20, todayOnly.Received);

        var week = handler.Handle(new ApiRequest { Op = ApiOps.Usage, Period = "7d" }, ClientRights.ReadOnly).Usage!;
        Assert.Equal("7d", week.Period);
        Assert.Equal([Chat, Browser], week.Apps.Select(a => a.App));
        Assert.Equal(DataUsageStore.DayText(today.AddDays(-6)), week.From);

        Assert.False(handler.Handle(new ApiRequest { Op = ApiOps.Usage, Period = "1y" }, ClientRights.ReadOnly).Ok);
        Assert.False(handler.Handle(new ApiRequest { Op = ApiOps.ResetUsage }, ClientRights.ReadOnly).Ok);
        Assert.False(store.ResetRequested);

        Assert.True(handler.Handle(new ApiRequest { Op = ApiOps.ResetUsage }, ClientRights.CrioFireApp).Ok);
        Assert.True(store.ResetRequested);
        Assert.Empty(handler.Handle(new ApiRequest { Op = ApiOps.Usage, Period = "30d" }, ClientRights.ReadOnly).Usage!.Apps);
    }

    [Theory]
    [InlineData(0, "0 bytes")]
    [InlineData(1, "1 byte")]
    [InlineData(1023, "1,023 bytes")]
    [InlineData(1536, "1.5 KB")]
    [InlineData(10L * 1024 * 1024, "10 MB")]
    [InlineData(250L * 1024 * 1024, "250 MB")]
    [InlineData(5L * 1024 * 1024 * 1024 + (400L * 1024 * 1024), "5.4 GB")]
    public void SizesReadNaturally(long bytes, string text) =>
        Assert.Equal(text, DataSize.Text(bytes, CultureInfo.InvariantCulture));

    [Fact]
    public void ProgramsAreShownByName()
    {
        Assert.Equal("browser.exe", DataSize.ProgramName(Browser));
        Assert.Contains("System", DataSize.ProgramName(KnownApps.Kernel), StringComparison.Ordinal);
        Assert.Contains("ended", DataSize.ProgramName(AppUsage.UnknownApp), StringComparison.Ordinal);
    }

    [Fact]
    public void TheCommandLineShowsAndClearsUsage()
    {
        var today = CommandLine.Parse(["usage"], out var error);
        Assert.Null(error);
        Assert.Equal(CommandKind.DataUsed, today.Kind);
        Assert.Equal("today", today.FilePath);

        Assert.Equal("30d", CommandLine.Parse(["usage", "30D"], out _).FilePath);
        Assert.True(CommandLine.Parse(["usage", "--reset"], out _).Replace);

        Assert.Equal(CommandKind.Help, CommandLine.Parse(["usage", "forever"], out error).Kind);
        Assert.NotNull(error);
    }

    /// <summary>A Kernel-Network send or receive event: PID, size, destination, source, then ports and more.</summary>
    private static byte[] Event(uint pid, uint size, byte[] destination, byte[] source)
    {
        var data = new List<byte>();
        data.AddRange(BitConverter.GetBytes(pid));
        data.AddRange(BitConverter.GetBytes(size));
        data.AddRange(destination);
        data.AddRange(source);
        data.AddRange(new byte[16]);   // ports, sequence number, connection id
        return [.. data];
    }
}
