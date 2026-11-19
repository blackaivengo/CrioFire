using System.Text.Json;
using System.Text.Json.Serialization;

namespace CrioFire.Server;

/// <summary>One thing an administrator did in the console (or tried to).</summary>
public sealed record AuditEntry(DateTime TimeUtc, string Who, string What, string? Detail, string? Address, bool Ok);

/// <summary>
/// %ProgramData%\criofire-server\audit.log: who changed what in the console and when, one JSON
/// line each. Passwords, license keys and enrollment codes are never written. At 2 MB the file
/// becomes audit.log.1 (replacing the one before), so two files at most are kept.
/// </summary>
public sealed class AuditLog(string folder)
{
    private const long MaxBytes = 2 * 1024 * 1024;
    private readonly Lock _gate = new();

    public string FilePath { get; } = Path.Combine(folder, "audit.log");

    public void Record(DateTime nowUtc, string? who, string what, string? detail, string? address, bool ok = true)
    {
        var entry = new AuditEntry(nowUtc, Clip(who, 64) ?? "-", what, Clip(detail, 300), Clip(address, 64), ok);
        lock (_gate)
        {
            try
            {
                Directory.CreateDirectory(folder);
                if (File.Exists(FilePath) && new FileInfo(FilePath).Length > MaxBytes)
                {
                    File.Move(FilePath, FilePath + ".1", overwrite: true);
                }

                File.AppendAllText(FilePath, JsonSerializer.Serialize(entry, AuditJson.Default.AuditEntry) + "\n");
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                // The change itself must not fail because its note could not be written.
            }
        }
    }

    /// <summary>The latest entries, newest first.</summary>
    public IReadOnlyList<AuditEntry> Latest(int limit)
    {
        var entries = new List<AuditEntry>();
        lock (_gate)
        {
            foreach (var path in new[] { FilePath + ".1", FilePath })
            {
                try
                {
                    if (!File.Exists(path))
                    {
                        continue;
                    }

                    foreach (var line in File.ReadLines(path))
                    {
                        try
                        {
                            if (JsonSerializer.Deserialize(line, AuditJson.Default.AuditEntry) is { } entry)
                            {
                                entries.Add(entry);
                            }
                        }
                        catch (JsonException)
                        {
                            // A damaged line: skip it.
                        }
                    }
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                {
                    // Unreadable right now: show what could be read.
                }
            }
        }

        entries.Reverse();
        return entries.Count > limit ? entries.GetRange(0, Math.Max(limit, 0)) : entries;
    }

    /// <summary>One line: no line breaks or control characters, whatever a name held.</summary>
    private static string? Clip(string? text, int max)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return null;
        }

        var clean = new string(text.Where(c => !char.IsControl(c)).ToArray()).Trim();
        return clean.Length > max ? clean[..max] : clean;
    }
}

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase, DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
[JsonSerializable(typeof(AuditEntry))]
internal sealed partial class AuditJson : JsonSerializerContext
{
}
