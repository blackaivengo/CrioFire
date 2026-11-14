using System.Globalization;
using System.Text;
using System.Text.Json.Serialization;

namespace CrioFire.Core;

/// <summary>
/// How much connection history the service keeps: blocked.log and allowed.log (with their
/// previous files, blocked.1.log and allowed.1.log).
/// </summary>
/// <param name="KeepDays">Lines older than this are removed (checked every hour).</param>
/// <param name="MaxMegabytes">The most each log may use on disk, the previous file included.</param>
/// <param name="RecordAllowed">Keep allowed.log at all. Off: reports, the allowed list and the
/// Traffic page show blocked connections only.</param>
public sealed record LogSettings(int KeepDays = LogSettings.DefaultKeepDays, int MaxMegabytes = LogSettings.DefaultMaxMegabytes, bool RecordAllowed = true)
{
    public const int DefaultKeepDays = 30;
    public const int DefaultMaxMegabytes = 20;
    public const int MinKeepDays = 1;
    public const int MaxKeepDays = 3650;
    public const int MinMegabytes = 2;
    public const int MaxMegabytesLimit = 2048;

    /// <summary>The choices the app offers; any value in range works from the command line.</summary>
    public static IReadOnlyList<int> KeepChoices { get; } = [7, 30, 90, 365];

    public static IReadOnlyList<int> SizeChoices { get; } = [20, 50, 200, 500];

    /// <summary>The size at which a log moves to its previous file: half the limit, so both fit in it.</summary>
    [JsonIgnore]
    public long RotateBytes => MaxMegabytes * 1024L * 1024L / 2;

    /// <summary>Why these settings cannot be used, or null.</summary>
    public string? Problem() =>
        KeepDays is < MinKeepDays or > MaxKeepDays ? $"Keep history for {MinKeepDays} to {MaxKeepDays} days."
        : MaxMegabytes is < MinMegabytes or > MaxMegabytesLimit ? $"Each log may use {MinMegabytes} to {MaxMegabytesLimit} MB."
        : null;

    /// <summary>"30 days", "1 year".</summary>
    public static string KeepText(int days) => days switch
    {
        1 => "1 day",
        365 => "1 year",
        730 => "2 years",
        _ => days.ToString(CultureInfo.InvariantCulture) + " days",
    };

    public string ToText() => string.Create(CultureInfo.InvariantCulture, $"keepDays={KeepDays}\nmaxMegabytes={MaxMegabytes}\nrecordAllowed={(RecordAllowed ? "on" : "off")}\n");

    /// <summary>Reads key=value lines; unknown keys, bad values and values out of range keep the default.</summary>
    public static LogSettings Parse(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        var settings = new LogSettings();
        foreach (var raw in text.Split('\n'))
        {
            var line = raw.Trim();
            var equals = line.IndexOf('=', StringComparison.Ordinal);
            if (line.StartsWith('#') || equals <= 0)
            {
                continue;
            }

            var key = line[..equals].Trim();
            var value = line[(equals + 1)..].Trim();
            if (key.Equals("keepDays", StringComparison.OrdinalIgnoreCase)
                && int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var days)
                && days is >= MinKeepDays and <= MaxKeepDays)
            {
                settings = settings with { KeepDays = days };
            }
            else if (key.Equals("maxMegabytes", StringComparison.OrdinalIgnoreCase)
                && int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var mb)
                && mb is >= MinMegabytes and <= MaxMegabytesLimit)
            {
                settings = settings with { MaxMegabytes = mb };
            }
            else if (key.Equals("recordAllowed", StringComparison.OrdinalIgnoreCase) && ParseSwitch(value) is { } on)
            {
                settings = settings with { RecordAllowed = on };
            }
        }

        return settings;
    }

    /// <summary>on/off, true/false, yes/no, 1/0.</summary>
    public static bool? ParseSwitch(string? value) => value?.Trim().ToLowerInvariant() switch
    {
        "on" or "true" or "yes" or "1" => true,
        "off" or "false" or "no" or "0" => false,
        _ => null,
    };
}

/// <summary>log-settings.txt in %ProgramData%\criofire. Missing or unreadable: the defaults.</summary>
public sealed class LogSettingsStore(string path)
{
    public static string DefaultPath => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "criofire", "log-settings.txt");

    public string FilePath { get; } = path;

    public LogSettings Load()
    {
        try
        {
            return File.Exists(FilePath) ? LogSettings.Parse(File.ReadAllText(FilePath)) : new LogSettings();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return new LogSettings();
        }
    }

    public void Save(LogSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);
        if (settings.Problem() is { } problem)
        {
            throw new ArgumentException(problem, nameof(settings));
        }

        Directory.CreateDirectory(Path.GetDirectoryName(FilePath)!);
        File.WriteAllText(FilePath + ".tmp", settings.ToText(), new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
        File.Move(FilePath + ".tmp", FilePath, overwrite: true);
    }
}

/// <summary>Removing old lines from the logs, clearing them, and how much they hold.</summary>
public static class LogRetention
{
    /// <summary>
    /// Removes lines older than <paramref name="cutoffUtc"/> from the log and its previous file
    /// (a file left empty is deleted). Lines without a readable time stay. Returns how many lines went.
    /// </summary>
    public static int Trim(TrafficLog log, DateTime cutoffUtc)
    {
        ArgumentNullException.ThrowIfNull(log);
        return TrimFile(log.RotatedPath, cutoffUtc) + TrimFile(log.Path, cutoffUtc);
    }

    /// <summary>Deletes the log and its previous file.</summary>
    public static void Clear(TrafficLog log)
    {
        ArgumentNullException.ThrowIfNull(log);
        foreach (var file in new[] { log.Path, log.RotatedPath })
        {
            for (var attempt = 0; ; attempt++)
            {
                try
                {
                    File.Delete(file);
                    break;
                }
                catch (IOException) when (attempt < 5)
                {
                    Thread.Sleep(100);   // the service is writing to it
                }
            }
        }
    }

    /// <summary>The bytes the log and its previous file use.</summary>
    public static long Bytes(TrafficLog log)
    {
        ArgumentNullException.ThrowIfNull(log);
        return new[] { log.Path, log.RotatedPath }.Where(File.Exists).Sum(f => new FileInfo(f).Length);
    }

    /// <summary>The time of the oldest line kept (in the previous file if there is one), or null.</summary>
    public static DateTime? OldestUtc(TrafficLog log)
    {
        ArgumentNullException.ThrowIfNull(log);
        foreach (var file in new[] { log.RotatedPath, log.Path }.Where(File.Exists))
        {
            try
            {
                foreach (var line in File.ReadLines(file).Take(20))
                {
                    if (TrafficHistory.Parse(line) is { } logged)
                    {
                        return logged.TimeUtc;
                    }
                }
            }
            catch (IOException)
            {
                // Being replaced: look at the other file.
            }
        }

        return null;
    }

    private static int TrimFile(string path, DateTime cutoffUtc)
    {
        // Lines are written in time order: nothing to do when the first one is recent enough, and
        // once one is, the rest is copied without reading it.
        if (!File.Exists(path) || File.ReadLines(path).Select(TrafficHistory.Parse).FirstOrDefault(l => l is not null) is not { } first
            || first.TimeUtc >= cutoffUtc)
        {
            return 0;
        }

        var temp = path + ".trim";
        var removed = 0;
        var kept = 0;
        using (var writer = new StreamWriter(temp, append: false, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false)))
        {
            var copying = false;
            foreach (var line in File.ReadLines(path))
            {
                if (!copying && TrafficHistory.Parse(line) is { } logged)
                {
                    if (logged.TimeUtc < cutoffUtc)
                    {
                        removed++;
                        continue;
                    }

                    copying = true;
                }

                if (line.Length > 0)
                {
                    writer.Write(line);
                    writer.Write('\n');
                    kept++;
                }
            }
        }

        if (kept == 0)
        {
            File.Delete(temp);
            File.Delete(path);
        }
        else
        {
            File.Move(temp, path, overwrite: true);
        }

        return removed;
    }
}
