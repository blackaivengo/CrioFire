using System.Text;

namespace CrioFire.Core;

/// <summary>
/// Appends blocked connections to <c>%ProgramData%\criofire\blocked.log</c>, one JSON object per
/// line. When the file passes <see cref="MaxBytes"/> it is renamed to <c>blocked.1.log</c>
/// (replacing the previous one), so the log never grows without bound.
/// </summary>
public sealed class TrafficLog
{
    public const long DefaultMaxBytes = 10 * 1024 * 1024;

    public TrafficLog(string path, long maxBytes = DefaultMaxBytes)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        Path = path;
        MaxBytes = maxBytes;
    }

    public static string DefaultPath => System.IO.Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "criofire", "blocked.log");

    public string Path { get; }

    public long MaxBytes { get; }

    public string RotatedPath => System.IO.Path.ChangeExtension(Path, ".1.log");

    public void Append(IEnumerable<BlockedConnection> connections)
    {
        ArgumentNullException.ThrowIfNull(connections);
        var lines = new StringBuilder();
        foreach (var c in connections)
        {
            lines.Append(c.ToJsonLine()).Append('\n');
        }

        if (lines.Length == 0)
        {
            return;
        }

        Directory.CreateDirectory(System.IO.Path.GetDirectoryName(System.IO.Path.GetFullPath(Path))!);
        if (File.Exists(Path) && new FileInfo(Path).Length >= MaxBytes)
        {
            File.Move(Path, RotatedPath, overwrite: true);
        }

        File.AppendAllText(Path, lines.ToString(), new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
    }
}

/// <summary>
/// Remembers the blocked connections seen in the last few seconds, so overlapping reads of the
/// engine's event history log each connection once. Pure logic, unit-tested.
/// </summary>
public sealed class RecentEvents(TimeSpan window)
{
    private readonly Dictionary<string, DateTime> _seen = [];

    public IReadOnlyList<BlockedConnection> KeepNew(IEnumerable<BlockedConnection> events, DateTime nowUtc)
    {
        ArgumentNullException.ThrowIfNull(events);

        // Forget what is older than twice the window; it can no longer be read again.
        var cutoff = nowUtc - (window + window);
        foreach (var stale in _seen.Where(kv => kv.Value < cutoff).Select(kv => kv.Key).ToList())
        {
            _seen.Remove(stale);
        }

        var fresh = new List<BlockedConnection>();
        foreach (var e in events)
        {
            var key = $"{e.TimeUtc.Ticks}|{e.FilterId}|{e.Local}|{e.Remote}|{(int)e.Protocol}";
            if (_seen.TryAdd(key, e.TimeUtc))
            {
                fresh.Add(e);
            }
        }

        return fresh;
    }
}
