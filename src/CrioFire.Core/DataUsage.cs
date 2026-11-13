using System.Globalization;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace CrioFire.Core;

/// <summary>Bytes one process sent or received in one go, as Windows reports it.</summary>
/// <param name="Loopback">Traffic that stays on this PC (127.0.0.1, ::1): not counted as data used.</param>
public readonly record struct NetworkTransfer(uint ProcessId, uint Bytes, bool Sent, bool Loopback);

/// <summary>
/// Follows how much each process sends and receives, through a real-time event tracing session on
/// the Microsoft-Windows-Kernel-Network provider: TCP and UDP, IPv4 and IPv6. Only process ids and
/// byte counts are read; nothing is written to disk here. Needs administrator or SYSTEM rights.
/// </summary>
public sealed class NetworkUsageEvents : IDisposable
{
    public const string SessionName = "CrioFire-Usage";

    private static readonly Guid KernelNetworkProvider = new("7dd42a49-5329-4832-8dfd-43d979153a88");

    private readonly RealTimeTrace _trace;
    private readonly Action<NetworkTransfer> _transfer;

    /// <param name="transfer">Called on the tracing thread for every send and receive: keep it quick.</param>
    public NetworkUsageEvents(Action<NetworkTransfer> transfer)
    {
        ArgumentNullException.ThrowIfNull(transfer);
        _transfer = transfer;

        // A busy PC raises thousands of these a second: larger and more buffers so none are lost.
        _trace = new RealTimeTrace(SessionName, "CrioFire data used", KernelNetworkProvider, OnEvent, bufferKb: 64, maxBuffers: 64);
    }

    public void Start() => _trace.Start();

    public void Dispose() => _trace.Dispose();

    private void OnEvent(ushort id, ReadOnlySpan<byte> data)
    {
        if (Parse(id, data) is { } transfer)
        {
            _transfer(transfer);
        }
    }

    /// <summary>
    /// Reads a send or receive event. Every one starts PID (UInt32), size (UInt32), then the
    /// destination and source addresses: 4 bytes each for IPv4, 16 for IPv6. Events 10/11 are TCP
    /// over IPv4 (sent/received), 26/27 TCP over IPv6, 42/43 UDP over IPv4, 58/59 UDP over IPv6.
    /// Null for every other event, or data too short.
    /// </summary>
    public static NetworkTransfer? Parse(ushort id, ReadOnlySpan<byte> data)
    {
        bool sent;
        bool v6;
        switch (id)
        {
            case 10 or 42: sent = true; v6 = false; break;
            case 11 or 43: sent = false; v6 = false; break;
            case 26 or 58: sent = true; v6 = true; break;
            case 27 or 59: sent = false; v6 = true; break;
            default: return null;
        }

        var addressLength = v6 ? 16 : 4;
        if (data.Length < 8 + (2 * addressLength))
        {
            return null;
        }

        var pid = MemoryMarshal.Read<uint>(data);
        var size = MemoryMarshal.Read<uint>(data[4..]);
        var destination = data.Slice(8, addressLength);
        var source = data.Slice(8 + addressLength, addressLength);
        return new NetworkTransfer(pid, size, sent, IsLoopback(destination) || IsLoopback(source));
    }

    private static bool IsLoopback(ReadOnlySpan<byte> address) =>
        address.Length == 4
            ? address[0] == 127
            : address[..15].IndexOfAnyExcept((byte)0) < 0 && address[15] == 1;
}

/// <summary>What one program sent and received (bytes).</summary>
/// <param name="App">The program's full path, "System" for Windows itself, or <see cref="UnknownApp"/>.</param>
public sealed record AppUsage(string App, long Sent, long Received)
{
    /// <summary>A process that ended before CrioFire could see which program it was.</summary>
    public const string UnknownApp = "unknown";

    [JsonIgnore]
    public long Total => Sent + Received;
}

/// <summary>Byte counts and program names as people read them.</summary>
public static class DataSize
{
    private static readonly string[] Units = ["bytes", "KB", "MB", "GB", "TB"];

    /// <summary>"512 bytes", "1.5 KB", "230 MB", "12.4 GB" (1 KB = 1024 bytes).</summary>
    public static string Text(long bytes, IFormatProvider culture)
    {
        if (bytes < 1024)
        {
            return string.Format(culture, "{0:N0} {1}", Math.Max(bytes, 0), bytes == 1 ? "byte" : Units[0]);
        }

        double value = bytes;
        var unit = 0;
        while (value >= 1024 && unit < Units.Length - 1)
        {
            value /= 1024;
            unit++;
        }

        return string.Format(culture, value < 100 ? "{0:0.#} {1}" : "{0:N0} {1}", value, Units[unit]);
    }

    /// <summary>The name to show for a counted program: its file name, or what "System" and "unknown" mean.</summary>
    public static string ProgramName(string app) => app switch
    {
        KnownApps.Kernel => "Windows kernel (System)",
        AppUsage.UnknownApp => "Programs that ended before CrioFire saw them",
        _ => app.LastIndexOfAny(['\\', '/']) is var slash && slash >= 0 && slash < app.Length - 1 ? app[(slash + 1)..] : app,
    };
}

/// <summary>One day's data used, per program. <paramref name="Day"/> is the local date, yyyy-MM-dd.</summary>
public sealed record UsageDay(string Day, List<AppUsage> Apps);

/// <summary>
/// Sums sends and receives per program between saves. <see cref="Add"/> runs on the tracing thread;
/// it learns which program a process is the first time it sees the process (and again after a
/// minute, in case Windows reused the id), so a program that ends straight after sending still counts.
/// </summary>
public sealed class DataCounter(Func<uint, string?> resolve)
{
    private const long NameLifetimeMs = 60_000;
    private const int MaxNames = 4096;

    private readonly Lock _gate = new();
    private readonly Dictionary<uint, (string App, long At)> _names = [];
    private Dictionary<string, (long Sent, long Received)> _counts = new(StringComparer.OrdinalIgnoreCase);

    public void Add(NetworkTransfer transfer) => Add(transfer, Environment.TickCount64);

    public void Add(NetworkTransfer transfer, long nowMs)
    {
        if (transfer.Loopback || transfer.Bytes == 0)
        {
            return;
        }

        lock (_gate)
        {
            var app = AppOf(transfer.ProcessId, nowMs);
            var (sent, received) = _counts.GetValueOrDefault(app);
            _counts[app] = transfer.Sent ? (sent + transfer.Bytes, received) : (sent, received + transfer.Bytes);
        }
    }

    /// <summary>The sums since the last call, and starts again from zero.</summary>
    public List<AppUsage> Take()
    {
        Dictionary<string, (long Sent, long Received)> counts;
        lock (_gate)
        {
            counts = _counts;
            _counts = new(StringComparer.OrdinalIgnoreCase);
        }

        return [.. counts.Select(c => new AppUsage(c.Key, c.Value.Sent, c.Value.Received))];
    }

    private string AppOf(uint pid, long nowMs)
    {
        if (pid is 0 or 4)
        {
            return KnownApps.Kernel;
        }

        if (_names.TryGetValue(pid, out var known) && nowMs - known.At < NameLifetimeMs)
        {
            return known.App;
        }

        var app = resolve(pid) is { Length: > 0 } path ? path : known.App ?? AppUsage.UnknownApp;
        if (_names.Count >= MaxNames)
        {
            foreach (var old in _names.Where(n => nowMs - n.Value.At >= NameLifetimeMs).Select(n => n.Key).ToList())
            {
                _names.Remove(old);
            }

            if (_names.Count >= MaxNames)
            {
                _names.Clear();
            }
        }

        _names[pid] = (app, nowMs);
        return app;
    }
}

/// <summary>The program a running process was started from.</summary>
public static partial class ProcessPaths
{
    private const uint ProcessQueryLimitedInformation = 0x1000;

    /// <summary>The full path of the process's program, or null if it has ended or cannot be read.</summary>
    public static unsafe string? Of(uint processId)
    {
        if (!OperatingSystem.IsWindows() || processId is 0 or 4)
        {
            return null;
        }

        var process = OpenProcess(ProcessQueryLimitedInformation, 0, processId);
        if (process == IntPtr.Zero)
        {
            return null;
        }

        try
        {
            var buffer = stackalloc char[1024];
            var length = 1024u;
            return QueryFullProcessImageNameW(process, 0, buffer, &length) != 0 ? new string(buffer, 0, (int)length) : null;
        }
        finally
        {
            _ = CloseHandle(process);
        }
    }

    [LibraryImport("kernel32.dll")]
    private static partial IntPtr OpenProcess(uint desiredAccess, int inheritHandle, uint processId);

    [LibraryImport("kernel32.dll")]
    private static unsafe partial int QueryFullProcessImageNameW(IntPtr process, uint flags, char* name, uint* size);

    [LibraryImport("kernel32.dll")]
    private static partial int CloseHandle(IntPtr handle);
}

/// <summary>
/// Data used per program and day, kept for <see cref="KeepDays"/> days in data-usage.json. Only the
/// service writes the file. Clearing the counts leaves a request file the service acts on, so the
/// two never write the same file.
/// </summary>
public sealed class DataUsageStore(string path)
{
    public const int KeepDays = 31;

    public static string DefaultPath => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "criofire", "data-usage.json");

    public string FilePath { get; } = path;

    public string ResetPath => Path.ChangeExtension(FilePath, ".reset");

    /// <summary>Someone asked to clear the counts and the service has not done it yet.</summary>
    public bool ResetRequested => File.Exists(ResetPath);

    public List<UsageDay> Load()
    {
        for (var attempt = 0; ; attempt++)
        {
            try
            {
                return File.Exists(FilePath)
                    ? JsonSerializer.Deserialize(File.ReadAllText(FilePath), DataUsageJson.Default.ListUsageDay) ?? []
                    : [];
            }
            catch (JsonException)
            {
                return [];
            }
            catch (IOException) when (attempt < 3)
            {
                Thread.Sleep(50);   // the service is replacing the file
            }
        }
    }

    public void Save(List<UsageDay> days)
    {
        ArgumentNullException.ThrowIfNull(days);
        Directory.CreateDirectory(Path.GetDirectoryName(FilePath)!);
        File.WriteAllText(FilePath + ".tmp", JsonSerializer.Serialize(days, DataUsageJson.Default.ListUsageDay));
        File.Move(FilePath + ".tmp", FilePath, overwrite: true);
    }

    public void RequestReset()
    {
        Directory.CreateDirectory(Path.GetDirectoryName(FilePath)!);
        File.WriteAllText(ResetPath, DateTime.UtcNow.ToString("O", CultureInfo.InvariantCulture));
    }

    /// <summary>The service: forget everything counted.</summary>
    public void CompleteReset()
    {
        File.Delete(FilePath);
        File.Delete(ResetPath);
    }

    public static string DayText(DateOnly day) => day.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);

    /// <summary>Adds sums to a day's counts, and drops days older than <paramref name="keepDays"/>.</summary>
    public static List<UsageDay> Merge(List<UsageDay> days, DateOnly day, IEnumerable<AppUsage> add, int keepDays = KeepDays)
    {
        ArgumentNullException.ThrowIfNull(days);
        ArgumentNullException.ThrowIfNull(add);
        var text = DayText(day);
        var oldest = DayText(day.AddDays(1 - keepDays));
        var result = days.Where(d => string.CompareOrdinal(d.Day, oldest) >= 0 && d.Day != text).ToList();
        var counts = (days.FirstOrDefault(d => d.Day == text)?.Apps ?? [])
            .Concat(add)
            .GroupBy(a => a.App, StringComparer.OrdinalIgnoreCase)
            .Select(g => new AppUsage(g.First().App, g.Sum(a => a.Sent), g.Sum(a => a.Received)))
            .OrderByDescending(a => a.Total)
            .ToList();
        result.Add(new UsageDay(text, counts));
        return [.. result.OrderBy(d => d.Day, StringComparer.Ordinal)];
    }

    /// <summary>Each program's sums from <paramref name="from"/> on, most data first.</summary>
    public static List<AppUsage> Totals(IEnumerable<UsageDay> days, DateOnly from)
    {
        ArgumentNullException.ThrowIfNull(days);
        var first = DayText(from);
        return [.. days
            .Where(d => string.CompareOrdinal(d.Day, first) >= 0)
            .SelectMany(d => d.Apps)
            .GroupBy(a => a.App, StringComparer.OrdinalIgnoreCase)
            .Select(g => new AppUsage(g.First().App, g.Sum(a => a.Sent), g.Sum(a => a.Received)))
            .OrderByDescending(a => a.Total)
            .ThenBy(a => a.App, StringComparer.OrdinalIgnoreCase)];
    }

    /// <summary>The first day a period covers: today, 7d or 30d (counting today).</summary>
    public static DateOnly PeriodStart(string? period, DateOnly today) => period?.Trim().ToLowerInvariant() switch
    {
        null or "" or "today" or "1d" => today,
        "7d" or "week" => today.AddDays(-6),
        "30d" or "month" => today.AddDays(-29),
        _ => throw new ArgumentException($"Unknown period '{period}': use today, 7d or 30d."),
    };
}

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(List<UsageDay>))]
internal sealed partial class DataUsageJson : JsonSerializerContext;
