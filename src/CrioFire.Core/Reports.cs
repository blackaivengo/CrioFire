using System.Globalization;
using System.Net;
using System.Text;
using System.Text.Json;

namespace CrioFire.Core;

/// <summary>
/// One line of the traffic logs: a blocked connection (blocked.log), or allowed connections summed
/// per minute (allowed.log, <paramref name="Allowed"/> true, with <paramref name="Count"/>,
/// <paramref name="Reason"/> and the service <paramref name="Port"/>; <paramref name="Remote"/> is then the address only).
/// </summary>
public sealed record LoggedEvent(
    DateTime TimeUtc,
    string? App,
    string? Protocol,
    string? Remote,
    string? Direction,
    string? Kind,
    bool Allowed = false,
    int Count = 1,
    string? Reason = null,
    string? Service = null,
    int Port = 0,
    string? Local = null,
    ulong FilterId = 0)
{
    /// <summary>Stopped by the mode's catch-all block (the program had no rule) rather than by a rule.</summary>
    public bool ByMode => Kind == nameof(FilterKind.DefaultBlock);
}

/// <summary>Reads blocked.log and blocked.1.log back. Tolerates partial and malformed lines.</summary>
public static class TrafficHistory
{
    public static LoggedEvent? Parse(string line) => Parse(line, null);

    /// <summary>With a <paramref name="pool"/>, equal texts (a program's path, "TCP") are one string for all lines.</summary>
    private static LoggedEvent? Parse(string line, Dictionary<string, string>? pool)
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

            if (r.TryGetProperty("allowed", out var allowed) && allowed.ValueKind == JsonValueKind.True)
            {
                var count = r.TryGetProperty("count", out var c) && c.TryGetInt32(out var n) && n > 0 ? n : 1;
                var port = r.TryGetProperty("port", out var p) && p.TryGetInt32(out var portNumber) ? portNumber : 0;
                return new LoggedEvent(
                    timeUtc, Shared(Text(r, "app"), pool), Shared(Text(r, "protocol"), pool), Text(r, "remote"), Shared(Text(r, "direction"), pool), null,
                    Allowed: true, Count: count, Reason: Shared(Text(r, "reason"), pool), Service: Shared(Text(r, "service"), pool), Port: port);
            }

            var filterId = r.TryGetProperty("filterId", out var f) && f.TryGetUInt64(out var id) ? id : 0;
            return new LoggedEvent(timeUtc, Shared(Text(r, "app"), pool), Shared(Text(r, "protocol"), pool), Text(r, "remote"), Shared(Text(r, "direction"), pool), Shared(Text(r, "kind"), pool),
                Local: Text(r, "local"), FilterId: filterId);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    /// <summary>Events at or after <paramref name="fromUtc"/> from several logs (e.g. blocked and allowed).</summary>
    public static IEnumerable<LoggedEvent> Read(IEnumerable<TrafficLog?> logs, DateTime fromUtc)
    {
        ArgumentNullException.ThrowIfNull(logs);
        foreach (var log in logs)
        {
            if (log is null)
            {
                continue;
            }

            foreach (var e in Read(log, fromUtc))
            {
                yield return e;
            }
        }
    }

    // Every line starts with {"time":"2026-11-20T14:46:54.1234567Z": 9 characters, then 28 that sort as text.
    private const string TimePrefix = "{\"time\":\"";
    private const int TimeLength = 28;

    /// <summary>Lines are written in order of time, give or take the minute a summary covers and the seconds between rounds.</summary>
    private static readonly TimeSpan OrderSlack = TimeSpan.FromMinutes(10);

    /// <summary>
    /// Events at or after <paramref name="fromUtc"/>, oldest file first. Safe while the service appends.
    /// The history can hold weeks and the app asks every few seconds, mostly for the last hour:
    /// reading starts where that time begins in the file (found by halving, as the lines are in
    /// order of time), older lines are skipped by their first characters without being parsed,
    /// and equal texts (a program's path, "TCP") are one string, not one per line.
    /// </summary>
    public static IEnumerable<LoggedEvent> Read(TrafficLog log, DateTime fromUtc)
    {
        ArgumentNullException.ThrowIfNull(log);
        var from = fromUtc.Kind == DateTimeKind.Local ? fromUtc.ToUniversalTime() : DateTime.SpecifyKind(fromUtc, DateTimeKind.Utc);
        var fromText = from.ToString("O", CultureInfo.InvariantCulture);
        var seekText = from - DateTime.MinValue > OrderSlack ? (from - OrderSlack).ToString("O", CultureInfo.InvariantCulture) : null;
        var pool = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var path in new[] { log.RotatedPath, log.Path })
        {
            if (!File.Exists(path))
            {
                continue;
            }

            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            if (seekText is not null)
            {
                stream.Position = FindStart(stream, seekText);
            }

            using var reader = new StreamReader(stream, Encoding.UTF8);
            while (reader.ReadLine() is { } line)
            {
                if (line.Length > TimePrefix.Length + TimeLength
                    && line[TimePrefix.Length + TimeLength - 1] == 'Z'
                    && line.StartsWith(TimePrefix, StringComparison.Ordinal)
                    && string.CompareOrdinal(line, TimePrefix.Length, fromText, 0, TimeLength) < 0)
                {
                    continue;   // older than asked for: not worth parsing
                }

                if (Parse(line, pool) is { } e && e.TimeUtc >= fromUtc)
                {
                    yield return e;
                }
            }
        }
    }

    /// <summary>
    /// A place in the file where a line starts and every line before it is older than
    /// <paramref name="timeText"/>: 0 unless the file is large. Never past the first line wanted,
    /// as long as lines are in order of time within <see cref="OrderSlack"/>.
    /// </summary>
    private static long FindStart(FileStream stream, string timeText)
    {
        const int near = 64 * 1024;   // the rest is read line by line
        long low = 0, high = stream.Length;
        var buffer = new byte[4096];
        while (high - low > near)
        {
            var middle = low + ((high - low) / 2);
            var time = TimeOfLineAfter(stream, middle, high, buffer, out var lineStart);
            if (time is not null && string.CompareOrdinal(time, timeText) < 0)
            {
                low = lineStart;
            }
            else
            {
                high = middle;
            }
        }

        return low;
    }

    /// <summary>The time text of the first whole, well-formed line starting after <paramref name="position"/> and before <paramref name="limit"/>; null when there is none.</summary>
    private static string? TimeOfLineAfter(FileStream stream, long position, long limit, byte[] buffer, out long lineStart)
    {
        lineStart = 0;
        var needed = TimePrefix.Length + TimeLength;
        var afterNewline = false;
        var held = new List<byte>(needed);
        stream.Position = position;
        var at = position;
        while (at < limit)
        {
            var read = stream.Read(buffer, 0, (int)Math.Min(buffer.Length, limit - at));
            if (read <= 0)
            {
                break;
            }

            for (var i = 0; i < read; i++)
            {
                var value = buffer[i];
                if (value == (byte)'\n')
                {
                    afterNewline = true;
                    held.Clear();
                    lineStart = at + i + 1;
                    continue;
                }

                if (!afterNewline)
                {
                    continue;
                }

                held.Add(value);
                if (held.Count == needed)
                {
                    var text = Encoding.ASCII.GetString(held.ToArray());
                    if (text.StartsWith(TimePrefix, StringComparison.Ordinal) && text[^1] == 'Z')
                    {
                        return text[TimePrefix.Length..];
                    }

                    afterNewline = false;   // not a line of ours: try the next one
                }
            }

            at += read;
        }

        return null;
    }

    private static string? Shared(string? text, Dictionary<string, string>? pool)
    {
        if (text is null || pool is null)
        {
            return text;
        }

        if (pool.TryGetValue(text, out var same))
        {
            return same;
        }

        if (pool.Count < 4096)
        {
            pool[text] = text;
        }

        return text;
    }

    private static string? Text(JsonElement r, string name) =>
        r.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
}

/// <param name="Allowed">Allowed connections in the bucket (not part of <see cref="Total"/>, which counts blocked ones).</param>
public sealed record ReportBucket(DateTime StartUtc, int ByRule, int ByMode, int Allowed = 0)
{
    public int Total => ByRule + ByMode;
}

public sealed record ReportProgram(string App, int Count, int ByRule, DateTime LastUtc);

public sealed record ReportDestination(string Address, int Port, int Count);

/// <summary>A program (or one service in svchost.exe) that was allowed to connect.</summary>
/// <param name="Reason">The most common reason it was allowed (an <see cref="AllowReason"/> name).</param>
/// <param name="Automatic">How many of its connections were allowed without a rule anyone made.</param>
/// <param name="Direction">out, in, or both.</param>
public sealed record ReportAllowedProgram(string App, string? Service, int Count, int Automatic, string Reason, string Direction, DateTime LastUtc);

public sealed record ReportReason(string Reason, int Count);

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
    List<ReportDestination> TopDestinations,
    int AllowedTotal = 0,
    int AllowedAutomatic = 0,
    int AllowedPrevious = 0,
    int AllowedProgramCount = 0,
    List<ReportReason>? AllowedReasons = null,
    List<ReportAllowedProgram>? TopAllowedPrograms = null,
    List<ReportDestination>? TopAllowedDestinations = null);

/// <summary>Builds a <see cref="ReportInfo"/> from logged events. Pure logic, unit-tested.</summary>
public static class ReportBuilder
{
    public const string Day = "24h";
    public const string Week = "7d";
    public const string Month = "30d";
    public const int TopCount = 10;

    /// <summary>Allowed programs get a longer list: the point is to see every one of them.</summary>
    public const int TopAllowedCount = 50;

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
        var allowedBuckets = new int[starts.Count];
        var allowedPrograms = new Dictionary<(string App, string Service), AllowedTally>();
        var allowedDestinations = new Dictionary<(string, int), int>();
        var reasons = new Dictionary<string, int>(StringComparer.Ordinal);
        int allowedTotal = 0, allowedAutomatic = 0, allowedPrevious = 0;
        var programs = new Dictionary<string, (int Count, int ByRule, DateTime Last)>(StringComparer.OrdinalIgnoreCase);
        var destinations = new Dictionary<(string, int), int>();
        int total = 0, rule = 0, mode = 0, outbound = 0, inbound = 0, previous = 0;

        foreach (var e in events)
        {
            var time = DateTime.SpecifyKind(e.TimeUtc, DateTimeKind.Utc);
            if (time >= previousFrom && time < fromUtc)
            {
                if (e.Allowed)
                {
                    allowedPrevious += e.Count;
                }
                else
                {
                    previous++;
                }

                continue;
            }

            if (time < fromUtc || time >= toUtc)
            {
                continue;
            }

            if (e.Allowed)
            {
                var n = e.Count;
                var reason = e.Reason ?? nameof(AllowReason.NoRule);
                var automatic = AllowReasons.IsAutomatic(reason);
                allowedTotal += n;
                allowedAutomatic += automatic ? n : 0;
                allowedBuckets[BucketIndex(starts, time)] += n;
                reasons[reason] = reasons.GetValueOrDefault(reason) + n;

                var key = (string.IsNullOrEmpty(e.App) ? "(unknown program)" : e.App, e.Service ?? string.Empty);
                if (!allowedPrograms.TryGetValue(key, out var tally))
                {
                    tally = new AllowedTally();
                    allowedPrograms[key] = tally;
                }

                tally.Add(n, automatic, reason, e.Direction, time);
                if (!string.IsNullOrEmpty(e.Remote))
                {
                    var dk = (e.Remote, e.Port);
                    allowedDestinations[dk] = allowedDestinations.GetValueOrDefault(dk) + n;
                }

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
            starts.Select((s, i) => new ReportBucket(s, byRule[i], byMode[i], allowedBuckets[i])).ToList(),
            programs.OrderByDescending(kv => kv.Value.Count).ThenBy(kv => kv.Key, StringComparer.OrdinalIgnoreCase).Take(TopCount)
                .Select(kv => new ReportProgram(kv.Key, kv.Value.Count, kv.Value.ByRule, kv.Value.Last)).ToList(),
            destinations.OrderByDescending(kv => kv.Value).ThenBy(kv => kv.Key.Item1, StringComparer.Ordinal).Take(TopCount)
                .Select(kv => new ReportDestination(kv.Key.Item1, kv.Key.Item2, kv.Value)).ToList(),
            allowedTotal,
            allowedAutomatic,
            allowedPrevious,
            allowedPrograms.Count,
            reasons.OrderByDescending(kv => kv.Value).ThenBy(kv => kv.Key, StringComparer.Ordinal)
                .Select(kv => new ReportReason(kv.Key, kv.Value)).ToList(),
            allowedPrograms.OrderByDescending(kv => kv.Value.Count).ThenBy(kv => kv.Key.App, StringComparer.OrdinalIgnoreCase).ThenBy(kv => kv.Key.Service, StringComparer.OrdinalIgnoreCase)
                .Take(TopAllowedCount)
                .Select(kv => new ReportAllowedProgram(
                    kv.Key.App, kv.Key.Service.Length == 0 ? null : kv.Key.Service, kv.Value.Count, kv.Value.Automatic,
                    kv.Value.TopReason, kv.Value.DirectionText, kv.Value.Last)).ToList(),
            allowedDestinations.OrderByDescending(kv => kv.Value).ThenBy(kv => kv.Key.Item1, StringComparer.Ordinal).Take(TopCount)
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
        sb.AppendLine(c, $"Allowed,{report.AllowedTotal}");
        sb.AppendLine(c, $"Allowed automatically,{report.AllowedAutomatic}");
        sb.AppendLine();
        sb.AppendLine("Period start,By your rules,No rule yet (mode),Blocked,Allowed");
        foreach (var b in report.Buckets)
        {
            sb.AppendLine(c, $"{Local(b.StartUtc)},{b.ByRule},{b.ByMode},{b.Total},{b.Allowed}");
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

        sb.AppendLine();
        sb.AppendLine("Allowed because,Connections");
        foreach (var r in report.AllowedReasons ?? [])
        {
            sb.AppendLine(c, $"{Quote(AllowReasons.Label(r.Reason, null))},{r.Count}");
        }

        sb.AppendLine();
        sb.AppendLine("Allowed program,Service,Direction,Allowed,Automatically,Main reason,Last seen");
        foreach (var p in report.TopAllowedPrograms ?? [])
        {
            sb.AppendLine(c, $"{Quote(p.App)},{Quote(p.Service ?? string.Empty)},{p.Direction},{p.Count},{p.Automatic},{Quote(AllowReasons.Label(p.Reason, p.Direction))},{Local(p.LastUtc)}");
        }

        sb.AppendLine();
        sb.AppendLine("Allowed destination,Port,Allowed");
        foreach (var d in report.TopAllowedDestinations ?? [])
        {
            sb.AppendLine(c, $"{Quote(d.Address)},{d.Port},{d.Count}");
        }

        return sb.ToString();
    }

    private sealed class AllowedTally
    {
        private readonly Dictionary<string, int> _reasons = new(StringComparer.Ordinal);
        private bool _out;
        private bool _in;

        public int Count { get; private set; }

        public int Automatic { get; private set; }

        public DateTime Last { get; private set; }

        public string TopReason => _reasons.OrderByDescending(kv => kv.Value).ThenBy(kv => kv.Key, StringComparer.Ordinal).First().Key;

        public string DirectionText => _out && _in ? "both" : _in ? "in" : "out";

        public void Add(int count, bool automatic, string reason, string? direction, DateTime time)
        {
            Count += count;
            Automatic += automatic ? count : 0;
            _reasons[reason] = _reasons.GetValueOrDefault(reason) + count;
            _in |= direction == "in";
            _out |= direction != "in";
            Last = time > Last ? time : Last;
        }
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

    /// <summary>
    /// One CSV cell. A text that a spreadsheet would take for a formula (it starts with =, +, @
    /// or -) gets an apostrophe in front: a program can name itself anything, and a report is
    /// opened in a spreadsheet.
    /// </summary>
    public static string Quote(string value)
    {
        if (value.Length > 0 && (value[0] is '=' or '+' or '@' or '\t' or '\r'
            || (value[0] == '-' && !double.TryParse(value, System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out _))))
        {
            value = "'" + value;
        }

        return value.AsSpan().IndexOfAny(',', '"', '\n') >= 0 || value.Contains('\r', StringComparison.Ordinal)
            ? "\"" + value.Replace("\"", "\"\"", StringComparison.Ordinal) + "\""
            : value;
    }
}
