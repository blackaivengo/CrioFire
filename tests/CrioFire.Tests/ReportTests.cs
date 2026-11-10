using System.Net;
using System.Net.Sockets;
using CrioFire.Core;
using CrioFire.Core.Api;

namespace CrioFire.Tests;

public sealed class ReportTests : IDisposable
{
    // Tuesday 2026-11-10 16:30 UTC; tests use UTC as "local" time so results don't depend on the machine.
    private static readonly DateTime Now = new(2026, 11, 10, 16, 30, 0, DateTimeKind.Utc);
    private static readonly TimeZoneInfo Utc = TimeZoneInfo.Utc;
    private readonly string _dir = Path.Combine(Path.GetTempPath(), $"criofire-report-{Guid.NewGuid():N}");

    public void Dispose()
    {
        if (Directory.Exists(_dir))
        {
            Directory.Delete(_dir, recursive: true);
        }
    }

    private static LoggedEvent Ev(DateTime t, string app = @"C:\a.exe", string? kind = "AppRule", string? remote = "203.0.113.5:443", string? dir = "out") =>
        new(t, app, "TCP", remote, dir, kind);

    [Fact]
    public void DayWindowIsTheLast24HoursUpToTheEndOfThisHour()
    {
        var (from, to, bucket) = ReportBuilder.Window(ReportBuilder.Day, Now, Utc);
        Assert.Equal(new DateTime(2026, 11, 10, 17, 0, 0, DateTimeKind.Utc), to);
        Assert.Equal(new DateTime(2026, 11, 9, 17, 0, 0, DateTimeKind.Utc), from);
        Assert.Equal(TimeSpan.FromHours(1), bucket);
    }

    [Fact]
    public void WeekWindowIsSevenWholeDaysIncludingToday()
    {
        var (from, to, bucket) = ReportBuilder.Window(ReportBuilder.Week, Now, Utc);
        Assert.Equal(new DateTime(2026, 11, 11, 0, 0, 0, DateTimeKind.Utc), to);
        Assert.Equal(new DateTime(2026, 11, 4, 0, 0, 0, DateTimeKind.Utc), from);
        Assert.Equal(TimeSpan.FromDays(1), bucket);
    }

    [Fact]
    public void CountsTotalsBucketsAndDirections()
    {
        var events = new[]
        {
            Ev(Now.AddMinutes(-10)),
            Ev(Now.AddMinutes(-20), kind: "DefaultBlock"),
            Ev(Now.AddHours(-3), dir: "in", remote: "198.51.100.7:3389"),
            Ev(Now.AddHours(-30)),          // the period before: only counted for the comparison
            Ev(Now.AddHours(-60)),          // older still: ignored
            Ev(Now.AddHours(2)),            // after the window (clock skew): ignored
        };

        var r = ReportBuilder.Build(events, ReportBuilder.Day, Now, Utc);

        Assert.Equal(3, r.Total);
        Assert.Equal(2, r.ByRule);
        Assert.Equal(1, r.ByMode);
        Assert.Equal(2, r.Outbound);
        Assert.Equal(1, r.Inbound);
        Assert.Equal(1, r.PreviousTotal);
        Assert.Equal(24, r.Buckets.Count);
        Assert.Equal(r.Total, r.Buckets.Sum(b => b.Total));

        var last = r.Buckets[^1];                                    // 16:00-17:00
        Assert.Equal(new DateTime(2026, 11, 10, 16, 0, 0, DateTimeKind.Utc), last.StartUtc);
        Assert.Equal(1, last.ByRule);
        Assert.Equal(1, last.ByMode);
        Assert.Equal(1, r.Buckets[^4].ByRule);                        // 13:00-14:00
    }

    [Fact]
    public void WeekBucketsAreDays()
    {
        var r = ReportBuilder.Build([Ev(Now), Ev(Now.AddDays(-1)), Ev(Now.AddDays(-6).Date.AddMinutes(1))], ReportBuilder.Week, Now, Utc);
        Assert.Equal(7, r.Buckets.Count);
        Assert.Equal(new DateTime(2026, 11, 4, 0, 0, 0, DateTimeKind.Utc), r.Buckets[0].StartUtc);
        Assert.Equal(new[] { 1, 0, 0, 0, 0, 1, 1 }, r.Buckets.Select(b => b.Total).ToArray());
    }

    [Fact]
    public void RanksProgramsAndDestinations()
    {
        var events = new List<LoggedEvent>();
        for (var i = 0; i < 5; i++)
        {
            events.Add(Ev(Now.AddMinutes(-i), app: @"C:\busy.exe", remote: "203.0.113.5:443"));
        }

        events.Add(Ev(Now.AddMinutes(-1), app: @"C:\BUSY.exe", kind: "DefaultBlock", remote: "[2001:db8::1]:443"));
        events.Add(Ev(Now.AddMinutes(-2), app: @"C:\quiet.exe", remote: "198.51.100.7:53"));
        events.Add(Ev(Now.AddMinutes(-3), app: "", remote: null));

        var r = ReportBuilder.Build(events, ReportBuilder.Day, Now, Utc);

        Assert.Equal(3, r.ProgramCount);
        var busy = r.TopPrograms[0];
        Assert.Equal(@"C:\busy.exe", busy.App);
        Assert.Equal(6, busy.Count);
        Assert.Equal(5, busy.ByRule);
        Assert.Equal(Now, busy.LastUtc);
        Assert.Contains(r.TopPrograms, p => p.App == "(unknown program)");

        Assert.Equal(3, r.DestinationCount);
        Assert.Equal(new ReportDestination("203.0.113.5", 443, 5), r.TopDestinations[0]);
        Assert.Contains(r.TopDestinations, d => d.Address == "2001:db8::1" && d.Port == 443);
    }

    [Fact]
    public void EmptyHistoryGivesAnEmptyReport()
    {
        var r = ReportBuilder.Build([], ReportBuilder.Month, Now, Utc);
        Assert.Equal(0, r.Total);
        Assert.Equal(30, r.Buckets.Count);
        Assert.Empty(r.TopPrograms);
    }

    [Fact]
    public void UnknownPeriodIsRefused()
    {
        Assert.False(ReportBuilder.IsPeriod("1y"));
        Assert.Throws<ArgumentException>(() => ReportBuilder.Build([], "1y", Now, Utc));
    }

    [Fact]
    public void LogLinesRoundTripIncludingTheKind()
    {
        var rule = new CrioFireFilter(7, "n", FilterLayers.All[0], null, FilterKind.DefaultBlock, FirewallMode.Ask);
        var blocked = new BlockedConnection(Now, @"C:\a.exe", ProtocolType.Tcp, null, new IPEndPoint(IPAddress.Parse("203.0.113.5"), 443), 7, rule);

        var back = TrafficHistory.Parse(blocked.ToJsonLine())!;
        Assert.Equal(Now, back.TimeUtc);
        Assert.Equal(@"C:\a.exe", back.App);
        Assert.Equal("203.0.113.5:443", back.Remote);
        Assert.True(back.ByMode);

        Assert.Null(TrafficHistory.Parse(""));
        Assert.Null(TrafficHistory.Parse("{\"time\":"));          // cut off mid-write
        Assert.Null(TrafficHistory.Parse("{\"app\":\"x\"}"));     // no time
        Assert.False(TrafficHistory.Parse("{\"time\":\"2026-11-10T16:30:00.0000000Z\"}")!.ByMode);   // old line, no kind
    }

    [Fact]
    public void ReadsBothLogFilesFromAGivenTime()
    {
        var log = new TrafficLog(Path.Combine(_dir, "blocked.log"));
        Directory.CreateDirectory(_dir);
        var older = new BlockedConnection(Now.AddDays(-2), @"C:\old.exe", ProtocolType.Udp, null, null, 1, null);
        var newer = new BlockedConnection(Now, @"C:\new.exe", ProtocolType.Tcp, null, null, 1, null);
        File.WriteAllText(log.RotatedPath, older.ToJsonLine() + "\n" + "garbage\n");
        File.WriteAllText(log.Path, newer.ToJsonLine() + "\n{\"time\":\"2026");   // last line still being written

        Assert.Equal(new[] { @"C:\old.exe", @"C:\new.exe" }, TrafficHistory.Read(log, Now.AddDays(-3)).Select(e => e.App).ToArray());
        Assert.Equal(@"C:\new.exe", Assert.Single(TrafficHistory.Read(log, Now.AddHours(-1))).App);
    }

    [Fact]
    public void CsvHasEverySectionAndQuotesCommas()
    {
        var r = ReportBuilder.Build([Ev(Now, app: @"C:\a, b\x.exe")], ReportBuilder.Day, Now, Utc);
        var csv = ReportBuilder.ToCsv(r, Utc);
        Assert.Contains("Blocked,1", csv);
        Assert.Contains("Period start,By your rules,No rule yet (mode),Blocked,Allowed", csv);
        Assert.Contains("\"C:\\a, b\\x.exe\",1,1,2026-11-10 16:30", csv);
        Assert.Contains("203.0.113.5,443,1", csv);
    }

    [Fact]
    public void ReportRoundTripsThroughTheApiJson()
    {
        var r = ReportBuilder.Build([Ev(Now)], ReportBuilder.Day, Now, Utc);
        var back = ApiJson.DeserializeResponse(ApiJson.Serialize(new ApiResponse { Ok = true, Report = r }))!.Report!;
        Assert.Equal(r.Total, back.Total);
        Assert.Equal(r.Buckets.Count, back.Buckets.Count);
        Assert.Equal(r.TopPrograms[0], back.TopPrograms[0]);
        Assert.Equal("7d", ApiJson.DeserializeRequest(ApiJson.Serialize(new ApiRequest { Op = ApiOps.Report, Period = "7d" }))!.Period);
    }
}
