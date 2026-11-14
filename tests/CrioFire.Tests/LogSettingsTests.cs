using System.Globalization;
using CrioFire.Cli;
using CrioFire.Core;
using CrioFire.Core.Api;

namespace CrioFire.Tests;

/// <summary>History settings: the file, trimming old lines, clearing, the API and the command line.</summary>
public sealed class LogSettingsTests : IDisposable
{
    private static readonly DateTime Now = new(2026, 11, 13, 12, 0, 0, DateTimeKind.Utc);

    private readonly string _dir = Path.Combine(Path.GetTempPath(), "criofire-logs-" + Guid.NewGuid().ToString("N"));

    public LogSettingsTests() => Directory.CreateDirectory(_dir);

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    [Fact]
    public void TheDefaultsKeepThirtyDaysAndTwentyMegabytes()
    {
        var settings = new LogSettings();
        Assert.Equal(30, settings.KeepDays);
        Assert.Equal(20, settings.MaxMegabytes);
        Assert.True(settings.RecordAllowed);
        Assert.Equal(10L * 1024 * 1024, settings.RotateBytes);   // the log and its previous file fit in the limit
        Assert.Equal(TrafficLog.DefaultMaxBytes, settings.RotateBytes);
        Assert.Null(settings.Problem());
    }

    [Fact]
    public void SettingsGoThroughTheFile()
    {
        var store = new LogSettingsStore(Path.Combine(_dir, "log-settings.txt"));
        Assert.Equal(new LogSettings(), store.Load());

        var changed = new LogSettings(KeepDays: 90, MaxMegabytes: 200, RecordAllowed: false);
        store.Save(changed);
        Assert.Equal(changed, store.Load());
        Assert.Contains("recordAllowed=off", File.ReadAllText(store.FilePath), StringComparison.Ordinal);
    }

    [Fact]
    public void BadOrUnknownLinesKeepTheDefaults()
    {
        var settings = LogSettings.Parse("# comment\nkeepDays=0\nmaxMegabytes=lots\nrecordAllowed=maybe\ncolour=blue\n");
        Assert.Equal(new LogSettings(), settings);

        Assert.Equal(new LogSettings(7, 500, false), LogSettings.Parse(" KEEPDAYS = 7 \r\nmaxmegabytes=500\r\nrecordallowed=no\r\n"));
    }

    [Fact]
    public void SettingsOutOfRangeAreRefused()
    {
        var store = new LogSettingsStore(Path.Combine(_dir, "log-settings.txt"));
        Assert.NotNull(new LogSettings(KeepDays: 0).Problem());
        Assert.NotNull(new LogSettings(KeepDays: 4000).Problem());
        Assert.NotNull(new LogSettings(MaxMegabytes: 1).Problem());
        Assert.NotNull(new LogSettings(MaxMegabytes: 5000).Problem());
        Assert.Throws<ArgumentException>(() => store.Save(new LogSettings(KeepDays: 0)));
        Assert.False(File.Exists(store.FilePath));
    }

    [Theory]
    [InlineData(1, "1 day")]
    [InlineData(30, "30 days")]
    [InlineData(365, "1 year")]
    public void KeepTimesReadNaturally(int days, string text) => Assert.Equal(text, LogSettings.KeepText(days));

    [Fact]
    public void TrimmingRemovesOldLinesFromBothFiles()
    {
        var log = new TrafficLog(Path.Combine(_dir, "blocked.log"));
        File.WriteAllText(log.RotatedPath, Lines(Now.AddDays(-50), Now.AddDays(-40)));
        File.WriteAllText(log.Path, Lines(Now.AddDays(-35), Now.AddDays(-31)) + "not json\n" + Lines(Now.AddDays(-2), Now.AddHours(-1)));

        var removed = LogRetention.Trim(log, Now.AddDays(-30));

        Assert.Equal(4, removed);
        Assert.False(File.Exists(log.RotatedPath));   // nothing recent was left in it
        var kept = File.ReadAllLines(log.Path);
        Assert.Equal(3, kept.Length);
        Assert.Equal("not json", kept[0]);
        Assert.Equal(Now.AddDays(-2), LogRetention.OldestUtc(log));
    }

    [Fact]
    public void ARecentLogIsLeftAlone()
    {
        var log = new TrafficLog(Path.Combine(_dir, "allowed.log"));
        File.WriteAllText(log.Path, Lines(Now.AddDays(-3), Now));
        var written = File.GetLastWriteTimeUtc(log.Path);

        Assert.Equal(0, LogRetention.Trim(log, Now.AddDays(-30)));
        Assert.Equal(written, File.GetLastWriteTimeUtc(log.Path));
        Assert.Equal(0, LogRetention.Trim(new TrafficLog(Path.Combine(_dir, "missing.log")), Now));
    }

    [Fact]
    public void ALogWithOnlyOldLinesIsDeleted()
    {
        var log = new TrafficLog(Path.Combine(_dir, "blocked.log"));
        File.WriteAllText(log.Path, Lines(Now.AddDays(-60)));

        Assert.Equal(1, LogRetention.Trim(log, Now.AddDays(-7)));
        Assert.False(File.Exists(log.Path));
        Assert.Null(LogRetention.OldestUtc(log));
        Assert.Equal(0, LogRetention.Bytes(log));
    }

    [Fact]
    public void ClearingDeletesTheLogAndItsPreviousFile()
    {
        var log = new TrafficLog(Path.Combine(_dir, "blocked.log"));
        File.WriteAllText(log.Path, Lines(Now));
        File.WriteAllText(log.RotatedPath, Lines(Now.AddDays(-1)));
        Assert.True(LogRetention.Bytes(log) > 0);

        LogRetention.Clear(log);

        Assert.False(File.Exists(log.Path));
        Assert.False(File.Exists(log.RotatedPath));
    }

    [Fact]
    public void TheApiShowsTheHistoryAndOnlyWritersChangeIt()
    {
        var blocked = new TrafficLog(Path.Combine(_dir, "blocked.log"));
        var allowed = new TrafficLog(Path.Combine(_dir, "allowed.log"));
        File.WriteAllText(blocked.Path, Lines(Now.AddDays(-5)));
        File.WriteAllText(allowed.Path, Lines(Now.AddDays(-9), Now));
        var store = new LogSettingsStore(Path.Combine(_dir, "log-settings.txt"));
        var handler = new ApiHandler(null!, trafficLog: blocked, allowedLog: allowed, logSettings: store);

        var info = handler.Handle(new ApiRequest { Op = ApiOps.Logs }, ClientRights.ReadOnly).Logs!;
        Assert.Equal(new LogSettings(), info.Settings);
        Assert.True(info.BlockedBytes > 0);
        Assert.True(info.AllowedBytes > info.BlockedBytes);
        Assert.Equal(Now.AddDays(-9), info.OldestUtc);

        var wanted = new LogSettings(KeepDays: 7);
        Assert.False(handler.Handle(new ApiRequest { Op = ApiOps.SetLogs, LogSettings = wanted }, ClientRights.ReadOnly).Ok);
        Assert.False(handler.Handle(new ApiRequest { Op = ApiOps.ClearLogs }, ClientRights.ReadOnly).Ok);
        Assert.False(handler.Handle(new ApiRequest { Op = ApiOps.SetLogs, LogSettings = new LogSettings(KeepDays: 0) }, ClientRights.Administrator).Ok);
        Assert.False(handler.Handle(new ApiRequest { Op = ApiOps.SetLogs }, ClientRights.Administrator).Ok);

        Assert.Equal(wanted, handler.Handle(new ApiRequest { Op = ApiOps.SetLogs, LogSettings = wanted }, ClientRights.Administrator).Logs!.Settings);
        Assert.Equal(wanted, store.Load());

        var cleared = handler.Handle(new ApiRequest { Op = ApiOps.ClearLogs }, ClientRights.Administrator).Logs!;
        Assert.Equal(0, cleared.BlockedBytes + cleared.AllowedBytes);
        Assert.Null(cleared.OldestUtc);
    }

    [Fact]
    public void TheSettingsTravelThroughTheApiAsJson()
    {
        var request = new ApiRequest { Op = ApiOps.SetLogs, LogSettings = new LogSettings(90, 50, false) };
        var back = ApiJson.DeserializeRequest(ApiJson.Serialize(request));
        Assert.Equal(request.LogSettings, back?.LogSettings);
    }

    [Fact]
    public void TheCommandLineShowsChangesAndClearsTheHistory()
    {
        var show = CommandLine.Parse(["logs"], out var error);
        Assert.Null(error);
        Assert.Equal(CommandKind.Logs, show.Kind);
        Assert.Null(show.KeepDays);
        Assert.False(show.RemoveData);

        var change = CommandLine.Parse(["logs", "--keep", "90", "--size", "200", "--allowed", "off"], out error);
        Assert.Null(error);
        Assert.Equal(90, change.KeepDays);
        Assert.Equal(200, change.MaxMegabytes);
        Assert.False(change.RecordAllowed ?? true);

        Assert.True(CommandLine.Parse(["logs", "--clear"], out _).RemoveData);
        Assert.Equal(CommandKind.Help, CommandLine.Parse(["logs", "--keep", "0"], out error).Kind);
        Assert.NotNull(error);
        Assert.Equal(CommandKind.Help, CommandLine.Parse(["logs", "--size"], out _).Kind);
        Assert.Equal(CommandKind.Help, CommandLine.Parse(["logs", "--everything"], out _).Kind);
    }

    /// <summary>Blocked-log lines at these times.</summary>
    private static string Lines(params DateTime[] times) =>
        string.Concat(times.Select(t => $"{{\"time\":\"{t.ToString("O", CultureInfo.InvariantCulture)}\",\"app\":\"C:\\\\Apps\\\\a.exe\"}}\n"));
}
