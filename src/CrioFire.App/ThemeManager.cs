using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;
using Microsoft.Win32;

namespace CrioFire.App;

/// <summary>
/// Light / dark / follow-Windows theme. Swaps the theme dictionary at index 0 of the app's
/// resources (every color is a DynamicResource, so the whole UI restyles live), matches the
/// Windows title bar, and remembers the choice in the app's preferences.
/// </summary>
internal static class ThemeManager
{
    public const string System = "system";
    public const string Light = "light";
    public const string Dark = "dark";

    public static string Choice { get; private set; } = System;

    public static bool IsDark { get; private set; } = true;

    public static event EventHandler? Changed;

    public static void Initialize()
    {
        Apply(Prefs.Current.Theme, save: false);
        SystemEvents.UserPreferenceChanged += (_, e) =>
        {
            if (Choice == System && e.Category == UserPreferenceCategory.General)
            {
                Application.Current?.Dispatcher.BeginInvoke(() => Apply(System, save: false));
            }
        };
    }

    public static void Toggle() => Apply(IsDark ? Light : Dark);

    public static void Apply(string choice, bool save = true)
    {
        Choice = choice is Light or Dark ? choice : System;
        IsDark = Choice switch
        {
            Light => false,
            Dark => true,
            _ => SystemUsesDarkApps(),
        };

        var dictionaries = Application.Current.Resources.MergedDictionaries;
        var theme = new ResourceDictionary { Source = new Uri($"pack://application:,,,/Themes/{(IsDark ? "Dark" : "Light")}.xaml") };
        if (dictionaries.Count > 0)
        {
            dictionaries[0] = theme;
        }
        else
        {
            dictionaries.Add(theme);
        }

        foreach (Window window in Application.Current.Windows)
        {
            TitleBar.Apply(window, IsDark);
        }

        if (save)
        {
            Prefs.Current.Theme = Choice;
            Prefs.Save();
        }

        Changed?.Invoke(null, EventArgs.Empty);
    }

    private static bool SystemUsesDarkApps()
    {
        using var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize");
        return key?.GetValue("AppsUseLightTheme") is int light && light == 0;
    }
}

/// <summary>Dark or light Windows title bar to match the theme (Windows 10 20H1+; caption color on Windows 11).</summary>
internal static partial class TitleBar
{
    private const int DWMWA_USE_IMMERSIVE_DARK_MODE = 20;
    private const int DWMWA_CAPTION_COLOR = 35;

    public static void Attach(Window window)
    {
        window.SourceInitialized += (_, _) => Apply(window, ThemeManager.IsDark);
    }

    public static void Apply(Window window, bool dark)
    {
        var hwnd = new WindowInteropHelper(window).Handle;
        if (hwnd == 0 || window.WindowStyle == WindowStyle.None)
        {
            return;
        }

        var value = dark ? 1 : 0;
        _ = DwmSetWindowAttribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE, ref value, sizeof(int));
        var caption = dark ? 0x00160C07 : 0x00F9F1E9;   // COLORREF 0x00BBGGRR of the window background
        _ = DwmSetWindowAttribute(hwnd, DWMWA_CAPTION_COLOR, ref caption, sizeof(int));
    }

    [LibraryImport("dwmapi.dll")]
    private static partial int DwmSetWindowAttribute(nint hwnd, int attribute, ref int value, int size);
}
