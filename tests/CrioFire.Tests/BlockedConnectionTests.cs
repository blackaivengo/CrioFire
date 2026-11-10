using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using CrioFire.Cli;
using CrioFire.Core;

namespace CrioFire.Tests;

public class BlockedConnectionTests
{
    private static readonly CrioFireFilter OutRule = new(
        42, "CrioFire: block app.exe", FilterLayers.ConnectV4, new RuleDescription(RuleAction.Block, TrafficDirection.Outbound, @"C:\a\app.exe"));

    [Theory]
    [InlineData(0x7F000001u, "127.0.0.1")]
    [InlineData(0xC0A80102u, "192.168.1.2")]
    [InlineData(0x08080808u, "8.8.8.8")]
    public void Ipv4IsDecodedFromHostOrder(uint value, string expected) =>
        Assert.Equal(IPAddress.Parse(expected), NetEventDecoding.FromHostOrderV4(value));

    [Fact]
    public void AppIdIsDecodedUpToTheTerminator()
    {
        var blob = Encoding.Unicode.GetBytes("\\device\\harddiskvolume3\\a\\app.exe\0garbage");
        Assert.Equal(@"\device\harddiskvolume3\a\app.exe", NetEventDecoding.DecodeAppId(blob));
        Assert.Null(NetEventDecoding.DecodeAppId([]));
    }

    [Fact]
    public void NtPathsMapToDriveLetters()
    {
        var mapper = new NtPathMapper([(@"\Device\HarddiskVolume1", "D:"), (@"\Device\HarddiskVolume10", "C:")]);
        Assert.Equal(@"C:\a\app.exe", mapper.ToDosPath(@"\device\harddiskvolume10\a\app.exe"));
        Assert.Equal(@"D:\x.exe", mapper.ToDosPath(@"\device\harddiskvolume1\x.exe"));
        Assert.Equal("System", mapper.ToDosPath("System"));
        Assert.Equal(@"\device\harddiskvolume11\x.exe", mapper.ToDosPath(@"\device\harddiskvolume11\x.exe"));
    }

    [Fact]
    public void DirectionComesFromTheCrioFireRule()
    {
        var ours = new BlockedConnection(DateTime.UtcNow, @"C:\a\app.exe", ProtocolType.Tcp, null, new IPEndPoint(IPAddress.Loopback, 80), 42, OutRule);
        var other = ours with { Rule = null, FilterId = 7 };
        Assert.True(ours.IsCrioFire);
        Assert.Equal(TrafficDirection.Outbound, ours.Direction);
        Assert.False(other.IsCrioFire);
        Assert.Null(other.Direction);
    }

    [Fact]
    public void JsonLineHasTheFields()
    {
        var e = new BlockedConnection(new DateTime(2026, 11, 9, 1, 2, 3, DateTimeKind.Utc), @"C:\a\app.exe", ProtocolType.Udp,
            new IPEndPoint(IPAddress.Parse("10.0.0.5"), 5353), new IPEndPoint(IPAddress.Parse("::1"), 53), 42, OutRule);
        using var doc = JsonDocument.Parse(e.ToJsonLine());
        var r = doc.RootElement;
        Assert.Equal(@"C:\a\app.exe", r.GetProperty("app").GetString());
        Assert.Equal("UDP", r.GetProperty("protocol").GetString());
        Assert.Equal("[::1]:53", r.GetProperty("remote").GetString());
        Assert.Equal("out", r.GetProperty("direction").GetString());
        Assert.Equal(42UL, r.GetProperty("filterId").GetUInt64());
        Assert.True(r.GetProperty("criofire").GetBoolean());
        Assert.DoesNotContain('\n', e.ToJsonLine());
    }

    [Fact]
    public void RecentEventsLogsEachConnectionOnce()
    {
        var t = DateTime.UtcNow;
        var a = new BlockedConnection(t, "x", ProtocolType.Tcp, null, new IPEndPoint(IPAddress.Loopback, 1), 1, null);
        var b = a with { TimeUtc = t.AddSeconds(1) };
        var recent = new RecentEvents(TimeSpan.FromSeconds(10));
        Assert.Single(recent.KeepNew([a], t));
        Assert.Equal(new[] { b }, recent.KeepNew([a, b], t.AddSeconds(2)));
        Assert.Empty(recent.KeepNew([a, b], t.AddSeconds(4)));
        Assert.Single(recent.KeepNew([a], t.AddMinutes(5)));   // long forgotten, counted again
    }

    [Fact]
    public void TrafficLogAppendsAndRotates()
    {
        var dir = Path.Combine(Path.GetTempPath(), $"criofire-log-{Guid.NewGuid():N}");
        try
        {
            var log = new TrafficLog(Path.Combine(dir, "blocked.log"), maxBytes: 200);
            var e = new BlockedConnection(DateTime.UtcNow, @"C:\a\app.exe", ProtocolType.Tcp, null, new IPEndPoint(IPAddress.Loopback, 80), 1, null);
            log.Append([e]);
            log.Append([e]);
            Assert.Equal(2, File.ReadAllLines(log.Path).Length);
            log.Append([e]);   // over 200 bytes: the old file moves aside
            Assert.True(File.Exists(log.RotatedPath));
            Assert.Single(File.ReadAllLines(log.Path));
            log.Append([]);
            Assert.Single(File.ReadAllLines(log.Path));
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Theory]
    [InlineData(new[] { "events" }, 10, false)]
    [InlineData(new[] { "events", "--all" }, 10, true)]
    [InlineData(new[] { "events", "--minutes", "60", "--all" }, 60, true)]
    public void EventsCommandParses(string[] args, int minutes, bool all)
    {
        var c = CommandLine.Parse(args, out var error);
        Assert.Null(error);
        Assert.Equal(new Command(CommandKind.Events, Minutes: minutes, All: all), c);
    }

    [Theory]
    [InlineData("events", "--minutes")]
    [InlineData("events", "--minutes", "0")]
    [InlineData("events", "--minutes", "abc")]
    [InlineData("events", "--everything")]
    public void BadEventsInputGivesAnError(params string[] args)
    {
        var c = CommandLine.Parse(args, out var error);
        Assert.NotNull(error);
        Assert.Equal(CommandKind.Help, c.Kind);
    }
}
