using System.Globalization;
using System.Text;
using CrioFire.Core;

namespace CrioFire.Tests;

public sealed class HistoryReadTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "criofire-history-" + Guid.NewGuid().ToString("N"));
    private static readonly DateTime Start = new(2026, 11, 1, 0, 0, 0, DateTimeKind.Utc);

    public HistoryReadTests() => Directory.CreateDirectory(_dir);

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private static string Line(DateTime timeUtc, int n) =>
        $"{{\"time\":\"{timeUtc.ToString("O", CultureInfo.InvariantCulture)}\",\"app\":\"C:\\\\Apps\\\\app{n % 7}.exe\",\"protocol\":\"TCP\",\"local\":\"10.0.0.2:{50000 + (n % 1000)}\",\"remote\":\"203.0.113.{n % 250}:443\",\"direction\":\"out\",\"kind\":\"rule\",\"filterId\":{n}}}";

    /// <summary>Weeks of history, one line every 30 seconds, a few a little out of order, some damaged.</summary>
    private TrafficLog Write(int lines)
    {
        var log = new TrafficLog(Path.Combine(_dir, "blocked.log"));
        var old = new StringBuilder();
        var current = new StringBuilder();
        for (var n = 0; n < lines; n++)
        {
            var time = Start.AddSeconds(30 * n);
            if (n % 97 == 0)
            {
                time = time.AddMinutes(-3);   // written late, as a summary of an earlier minute is
            }

            var target = n < lines / 2 ? old : current;
            target.Append(Line(time, n)).Append('\n');
            if (n % 501 == 0)
            {
                target.Append("not a line of the log\n\n{\"time\":\"broken\n");
            }
        }

        File.WriteAllText(log.RotatedPath, old.ToString());
        File.WriteAllText(log.Path, current.ToString());
        return log;
    }

    private static List<LoggedEvent> Everything(TrafficLog log) =>
        [.. new[] { log.RotatedPath, log.Path }.SelectMany(File.ReadLines).Select(TrafficHistory.Parse).Where(e => e is not null).Select(e => e!)];

    [Theory]
    [InlineData(0)]          // everything
    [InlineData(100)]        // from early in the older file
    [InlineData(9_999)]      // around where the files meet
    [InlineData(10_000)]
    [InlineData(15_000)]
    [InlineData(19_880)]     // the last hour
    [InlineData(19_999)]     // the last line
    [InlineData(25_000)]     // later than anything
    public void ReadingFromATimeGivesExactlyTheLinesSince(int fromLine)
    {
        var log = Write(20_000);   // about 3 MB: far more than is read line by line
        var from = Start.AddSeconds(30 * fromLine);
        var expected = Everything(log).Where(e => e.TimeUtc >= from).ToList();

        var read = TrafficHistory.Read(log, from).ToList();

        Assert.Equal(expected.Count, read.Count);
        Assert.Equal(expected.Select(e => (e.TimeUtc, e.FilterId)).ToArray(), read.Select(e => (e.TimeUtc, e.FilterId)).ToArray());
    }

    [Fact]
    public void TheLastHourOfALongHistoryIsReadWithoutReadingTheRest()
    {
        var log = Write(20_000);
        var all = Measure(() => TrafficHistory.Read(log, DateTime.MinValue).Count());
        var lastHour = Measure(() => TrafficHistory.Read(log, Start.AddSeconds(30 * 19_880)).Count());

        // The whole history costs megabytes; its last hour a small part of that.
        Assert.True(lastHour * 10 < all, $"reading the last hour allocated {lastHour:N0} bytes, the whole history {all:N0}");
    }

    [Fact]
    public void EqualTextsAreOneString()
    {
        var log = Write(2_000);
        var read = TrafficHistory.Read(log, DateTime.MinValue).ToList();

        Assert.Equal(7, read.Select(e => e.App).Distinct().Count());
        Assert.Equal(7, read.Select(e => e.App!).Distinct(ReferenceEqualityComparer.Instance).Count());
    }

    private static long Measure(Func<int> work)
    {
        var before = GC.GetAllocatedBytesForCurrentThread();
        work();
        return GC.GetAllocatedBytesForCurrentThread() - before;
    }
}
