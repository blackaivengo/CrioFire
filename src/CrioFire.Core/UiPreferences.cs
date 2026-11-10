using System.Globalization;
using System.Text;

namespace CrioFire.Core;

/// <summary>
/// The desktop app's per-user preferences, stored as simple "key=value" lines in
/// %LocalAppData%\CrioFire\ui.txt. Unknown keys are kept; a file holding only a theme name
/// (the first version's format) is read as the theme.
/// </summary>
public sealed class UiPreferences
{
    private readonly Dictionary<string, string> _values = new(StringComparer.OrdinalIgnoreCase);

    public static string DefaultPath { get; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "CrioFire", "ui.txt");

    /// <summary>system, light or dark.</summary>
    public string Theme
    {
        get => Get("theme") is "light" or "dark" ? Get("theme")! : "system";
        set => _values["theme"] = value;
    }

    /// <summary>Closing the window keeps CrioFire running in the notification area.</summary>
    public bool CloseToTray
    {
        get => GetBool("closeToTray", true);
        set => _values["closeToTray"] = value ? "true" : "false";
    }

    /// <summary>The "still running in the tray" hint has been shown once.</summary>
    public bool TrayHintShown
    {
        get => GetBool("trayHintShown", false);
        set => _values["trayHintShown"] = value ? "true" : "false";
    }

    /// <summary>The user has been asked once whether CrioFire should start with Windows.</summary>
    public bool AutostartAsked
    {
        get => GetBool("autostartAsked", false);
        set => _values["autostartAsked"] = value ? "true" : "false";
    }

    public static UiPreferences Parse(string text)
    {
        var prefs = new UiPreferences();
        var lines = (text ?? string.Empty).Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        foreach (var line in lines)
        {
            var eq = line.IndexOf('=', StringComparison.Ordinal);
            if (eq > 0)
            {
                prefs._values[line[..eq].Trim()] = line[(eq + 1)..].Trim();
            }
            else if (lines.Length == 1)
            {
                prefs._values["theme"] = line;   // version 1: the file held just the theme
            }
        }

        return prefs;
    }

    public string Format()
    {
        var sb = new StringBuilder();
        foreach (var (key, value) in _values.OrderBy(kv => kv.Key, StringComparer.Ordinal))
        {
            sb.Append(CultureInfo.InvariantCulture, $"{key}={value}\n");
        }

        return sb.ToString();
    }

    public static UiPreferences Load(string? path = null)
    {
        try
        {
            path ??= DefaultPath;
            return File.Exists(path) ? Parse(File.ReadAllText(path)) : new UiPreferences();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return new UiPreferences();
        }
    }

    /// <summary>Saves; returns false if the file could not be written (not remembering is harmless).</summary>
    public bool Save(string? path = null)
    {
        try
        {
            path ??= DefaultPath;
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.WriteAllText(path, Format());
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    private string? Get(string key) => _values.TryGetValue(key, out var v) ? v : null;

    private bool GetBool(string key, bool fallback) => Get(key) switch
    {
        "true" => true,
        "false" => false,
        _ => fallback,
    };
}

/// <summary>The command line Windows runs at sign-in to start the app quietly in the tray.</summary>
public static class AutostartCommand
{
    public const string TrayArgument = "--tray";
    public const string RunKey = @"Software\Microsoft\Windows\CurrentVersion\Run";
    public const string ValueName = "CrioFire";

    public static string For(string exePath) => $"\"{exePath}\" {TrayArgument}";

    /// <summary>True if a Run value starts this executable (quoted or not, any arguments).</summary>
    public static bool Points(string? command, string exePath)
    {
        if (string.IsNullOrWhiteSpace(command))
        {
            return false;
        }

        var c = command.Trim();
        var target = c.StartsWith('"') && c.IndexOf('"', 1) is var end and > 0 ? c[1..end] : c.Split(' ')[0];
        return string.Equals(Path.GetFullPath(target), Path.GetFullPath(exePath), StringComparison.OrdinalIgnoreCase);
    }
}
