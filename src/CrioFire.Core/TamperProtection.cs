using System.Text.Json;
using System.Text.Json.Serialization;

namespace CrioFire.Core;

/// <summary>
/// Tamper protection: when on, rules can only be changed with administrator approval. Without it,
/// CrioFire's own app and command line may change rules for any signed-in user, so a harmful
/// program running as that user could start criofire.exe to allow itself. With it, every change
/// needs an elevated (UAC-approved) CrioFire, or an administrator prompt. Kept in
/// %ProgramData%\criofire\protection.json, which only administrators and the service may write.
/// </summary>
public sealed class TamperProtection(string path)
{
    private static readonly Lock Gate = new();

    public static string DefaultPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "criofire", "protection.json");

    public string FilePath { get; } = path;

    public bool RequireAdmin
    {
        get
        {
            lock (Gate)
            {
                return Load().RequireAdmin;
            }
        }
    }

    public void SetRequireAdmin(bool on)
    {
        lock (Gate)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(FilePath))!);
            var temp = FilePath + ".tmp";
            File.WriteAllText(temp, JsonSerializer.Serialize(new ProtectionSettings { RequireAdmin = on }, ProtectionJson.Default.ProtectionSettings));
            File.Move(temp, FilePath, overwrite: true);
        }
    }

    private ProtectionSettings Load()
    {
        try
        {
            return File.Exists(FilePath)
                ? JsonSerializer.Deserialize(File.ReadAllText(FilePath), ProtectionJson.Default.ProtectionSettings) ?? new ProtectionSettings()
                : new ProtectionSettings();
        }
        catch (JsonException)
        {
            // A damaged file must not silently weaken protection: treat it as on.
            return new ProtectionSettings { RequireAdmin = true };
        }
        catch (IOException)
        {
            return new ProtectionSettings { RequireAdmin = true };
        }
    }
}

internal sealed class ProtectionSettings
{
    public bool RequireAdmin { get; set; }
}

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase, WriteIndented = true)]
[JsonSerializable(typeof(ProtectionSettings))]
internal sealed partial class ProtectionJson : JsonSerializerContext
{
}
