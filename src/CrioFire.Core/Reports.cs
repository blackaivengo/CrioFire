using System.Globalization;
using System.Net;
using System.Text;
using System.Text.Json;

namespace CrioFire.Core;

/// <summary>One blocked connection as read back from the traffic log.</summary>
public sealed record LoggedEvent(DateTime TimeUtc, string? App, string? Protocol, string? Remote, string? Direction, string? Kind)
{
    /// <summary>Stopped by the mode's catch-all block (the program had no rule) rather than by a rule.</summary>
    public bool ByMode => Kind == nameof(FilterKind.DefaultBlock);
}

/// <summary>Reads blocked.log and blocked.1.log back. Tolerates partial and malformed lines.</summary>
public static class TrafficHistory
{
    public static LoggedEvent? Parse(string line)
    {
        if (string.IsNullOrWhiteSpace(line))
        {
            return null;
        }

        try
        {
            using var doc = JsonDocument.Parse(line);
            var r = doc.RootElement;
            if (r.ValueKind != JsonValueKind.Object
                || !r.TryGetProperty("time", out var time)
                || !DateTime.TryParse(time.GetString(), CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out var timeUtc))
            {
                return null;
            }

            return new LoggedEvent(timeUtc, Text(r, "app"), Text(r, "protocol"), Text(r, "remote"), Text(r, "direction"), Text(r, "kind"));
        }
        catch (JsonException)
        {
            return null;
        }
    }

    /// <summary>Events at or after <paramref name="fromUtc"/>, oldest file first. Safe while the service appends.</summary>
    public static IEnumerable<LoggedEvent> Read(TrafficLog log, DateTime fromUtc)
    {
        ArgumentNullException.ThrowIfNull(log);
        foreach (var path in new[] { log.RotatedPath, log.Path })
        {
            if (!File.Exists(path))
            {
                continue;
            }

            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var reader = new StreamReader(stream, Encoding.UTF8);
            while (reader.ReadLine() is { } line)
            {
                if (Parse(line) is { } e && e.TimeUtc >= fromUtc)
                {
                    yield return e;
                }
            }
        }
    }

    private static string? Text(JsonElement r, string name) =>
        r.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
}

public sealed record ReportBucket(DateTime StartUtc, int ByRule, int ByMode)
{
    public int Total => ByRule + ByMode;
}

public sealed record ReportProgram(string App, int Count, int ByRule, DateTime LastUtc);

public sealed record ReportDestination(string Address, int Port, int Count);

/// <summary>What CrioFire blocked over a period: totals, a time series and the top programs and destinations.</summary>
public sealed record ReportInfo(
    string Period,
    DateTime FromUtc,
    DateTime ToUtc,
    int Total,
    int ByRule,
    int ByMode,
    int Outbound,
    int Inbound,
    int PreviousTotal,
    int ProgramCount,
    int DestinationCount,
    List<ReportBucket> Buckets,
    List<ReportProgram> TopPrograms,
    List<ReportDestination> TopDestinations);

/// <summary>Builds a <see cref="ReportInfo"/> from logged events. Pure logic, unit-tested.</summary>
public static class ReportBuilder
{
    public const string Day = "24h";
    public const string Week = "7d";
    public const string Month = "30d";
    public const int TopCount = 10;

    public static bool IsPeriod(string? period) => period is Day or Week or Month;

    /// <summary>
    /// The window a report covers. 24h: the 24 hours up to the end of the current hour.
    /// 7d/30d: whole local days, today included. Also returns the bucket size.
    /// </summary>
    public static (DateTime FromUtc, DateTime ToUtc, TimeSpan Bucket) Window(string period, DateTime nowUtc, TimeZoneInfo zone)
    {
        ArgumentNullException.ThrowIfNull(zone);
        var local = TimeZoneInfo.ConvertTimeFromUtc(DateTime.SpecifyKind(nowUtc, DateTimeKind.Utc), zone);
        if (period == Day)
        {
            var hourEnd = new DateTime(local.Year, local.Month, local.Day, local.Hour, 0, 0, DateTimeKind.Unspecified).AddHours(1);
            var toUtc = ToUtc(hourEnd, zone);
            return (toUtc.AddHours(-24), toUtc, TimeSpan.FromHours(1));
        }

        var days = period == Month ? 30 : 7;
        var tomorrow = local.Date.AddDays(1);
        return (ToUtc(tomorrow.AddDays(-days), zone), ToUtc(tomorrow, zone), TimeSpan.FromDays(1));
    }

    public static ReportInfo Build(IEnumerable<LoggedEvent> events, string period, DateTime nowUtc, TimeZoneInfo? zone = null)
    {
        ArgumentNullException.ThrowIfNull(events);
        if (!IsPeriod(period))
        {
            throw new ArgumentException("period must be 24h, 7d or 30d.");
        }

        zone ??= TimeZoneInfo.Local;
        var (fromUtc, toUtc, bucket) = Window(period, nowUtc, zone);
        var previousFrom = fromUtc - (toUtc - fromUtc);

        // Bucket starts in local time (days start at local midnight), stored as UTC.
        var starts = new List<DateTime>();
        var localStart = TimeZoneInfo.ConvertTimeFromUtc(fromUtc, zone);
        var localEnd = TimeZoneInfo.ConvertTimeFromUtc(toUtc, zone);
        for (var t = localStart; t < localEnd; t += bucket)
        {
            starts.Add(ToUtc(t, zone));
        }

        var byRule = new int[starts.Count];
        var byMode = new int[starts.Count];
        var programs = new Dictionary<string, (int Count, int ByRule, DateTime Last)>(StringComparer.OrdinalIgnoreCase);
        var destinations = new Dictionary<(string, int), int>();
        int total = 0, rule = 0, mode = 0, outbound = 0, inbound = 0, previous = 0;

        foreach (var e in events)
        {
            var time = DateTime.SpecifyKind(e.TimeUtc, DateTimeKind.Utc);
            if (time >= previousFrom && time < fromUtc)
            {
                previous++;
                continue;
            }

            if (time < fromUtc || time >= toUtc)
            {
                continue;
            }

            total++;
            var index = BucketIndex(starts, time);
            if (e.ByMode)
            {
                mode++;
                byMode[index]++;
            }
            else
            {
                rule++;
                byRule[index]++;
            }

            if (e.Direction == "out")
            {
                outbound++;
            }
            else if (e.Direction == "in")
            {
                inbound++;
            }

            var app = string.IsNullOrEmpty(e.App) ? "(unknown program)" : e.App;
            programs.TryGetValue(app, out var p);
            programs[app] = (p.Count + 1, p.ByRule + (e.ByMode ? 0 : 1), time > p.Last ? time : p.Last);

            if (e.Remote is not null && IPEndPoint.TryParse(e.Remote, out var remote))
            {
                var key = (remote.Address.ToString(), remote.Port);
                destinations[key] = destinations.GetValueOrDefault(key) + 1;
            }
        }

        return new ReportInfo(
            period, fromUtc, toUtc, total, rule, mode, outbound, inbound, previous,
            programs.Count, destinations.Count,
            starts.Select((s, i) => new ReportBucket(s, byRule[i], byMode[i])).ToList(),
            programs.OrderByDescending(kv => kv.Value.Count).ThenBy(kv => kv.Key, StringComparer.OrdinalIgnoreCase).Take(TopCount)
                .Select(kv => new ReportProgram(kv.Key, kv.Value.Count, kv.Value.ByRule, kv.Value.Last)).ToList(),
            destinations.OrderByDescending(kv => kv.Value).ThenBy(kv => kv.Key.Item1, StringComparer.Ordinal).Take(TopCount)
                .Select(kv => new ReportDestination(kv.Key.Item1, kv.Key.Item2, kv.Value)).ToList());
    }

    /// <summary>The report as CSV (summary, time series, programs, destinations), for spreadsheets.</summary>
    public static string ToCsv(ReportInfo report, TimeZoneInfo? zone = null)
    {
        ArgumentNullException.ThrowIfNull(report);
        zone ??= TimeZoneInfo.Local;
        var c = CultureInfo.InvariantCulture;
        var sb = new StringBuilder();
        string Local(DateTime utc) => TimeZoneInfo.ConvertTimeFromUtc(DateTime.SpecifyKind(utc, DateTimeKind.Utc), zone).ToString("yyyy-MM-dd HH:mm", c);

        sb.AppendLine("CrioFire report");
        sb.AppendLine(c, $"From,{Local(report.FromUtc)}");
        sb.AppendLine(c, $"To,{Local(report.ToUtc)}");
        sb.AppendLine(c, $"Blocked,{report.Total}");
        sb.AppendLine(c, $"By your rules,{report.ByRule}");
        sb.AppendLine(c, $"No rule yet (mode),{report.ByMode}");
        sb.AppendLine(c, $"Outbound,{report.Outbound}");
        sb.AppendLine(c, $"Inbound,{report.Inbound}");
        sb.AppendLine();
        sb.AppendLine("Period start,By your rules,No rule yet (mode),Total");
        foreach (var b in report.Buckets)
        {
            sb.AppendLine(c, $"{Local(b.StartUtc)},{b.ByRule},{b.ByMode},{b.Total}");
        }

        sb.AppendLine();
        sb.AppendLine("Program,Blocked,By your rules,Last seen");
        foreach (var p in report.TopPrograms)
        {
            sb.AppendLine(c, $"{Quote(p.App)},{p.Count},{p.ByRule},{Local(p.LastUtc)}");
        }

        sb.AppendLine();
        sb.AppendLine("Destination,Port,Blocked");
        foreach (var d in report.TopDestinations)
        {
            sb.AppendLine(c, $"{Quote(d.Address)},{d.Port},{d.Count}");
        }

        return sb.ToString();
    }

    private static int BucketIndex(List<DateTime> starts, DateTime time)
    {
        var index = starts.BinarySearch(time);
        return index >= 0 ? index : Math.Max(0, ~index - 1);
    }

    private static DateTime ToUtc(DateTime local, TimeZoneInfo zone)
    {
        var unspecified = DateTime.SpecifyKind(local, DateTimeKind.Unspecified);
        if (zone.IsInvalidTime(unspecified))
        {
            unspecified = unspecified.AddHours(1);   // a spring-forward gap
        }

        return TimeZoneInfo.ConvertTimeToUtc(unspecified, zone);
    }

    private static string Quote(string value) =>
        value.Contains(',', StringComparison.Ordinal) || value.Contains('"', StringComparison.Ordinal)
            ? "\"" + value.Replace("\"", "\"\"", StringComparison.Ordinal) + "\""
            : value;
}
