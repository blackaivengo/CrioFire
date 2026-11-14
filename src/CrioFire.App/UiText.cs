using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Controls;
using System.Windows.Data;
using CrioFire.Core;

namespace CrioFire.App;

/// <summary>
/// Puts the app in the user's language. Texts in code go through <see cref="L.T(string)"/>; texts
/// written in XAML stay English there and are translated here as each element loads (text, button
/// and check box captions, headers, tooltips, accessibility names, window titles, list column
/// headers), so the XAML needs no changes. Arabic and Urdu windows are mirrored.
/// </summary>
internal static class UiText
{
    private static bool _hooked;

    /// <summary>Picks the language (the user's choice, else the Windows display language) and starts translating.</summary>
    public static void Start()
    {
        var language = Languages.Resolve(Prefs.Current.Language, CultureInfo.CurrentUICulture);
        var catalog = Load(language);
        L.Use(language, catalog);
        if ((catalog.Count > 0 || language.RightToLeft) && !_hooked)
        {
            _hooked = true;
            EventManager.RegisterClassHandler(typeof(FrameworkElement), FrameworkElement.LoadedEvent, new RoutedEventHandler(OnLoaded), handledEventsToo: true);
        }
    }

    /// <summary>The translations shipped in the app for a language; empty for English or a missing file.</summary>
    public static Catalog Load(Language language)
    {
        ArgumentNullException.ThrowIfNull(language);
        if (language.Code == Languages.English)
        {
            return Catalog.Empty;
        }

        try
        {
            using var stream = typeof(UiText).Assembly.GetManifestResourceStream($"CrioFire.App.Strings.{language.Code}.json");
            if (stream is null)
            {
                return Catalog.Empty;
            }

            using var reader = new StreamReader(stream);
            return Catalog.Parse(reader.ReadToEnd());
        }
        catch (System.Text.Json.JsonException)
        {
            return Catalog.Empty;   // a broken file: English rather than no app
        }
    }

    /// <summary>Starts a new copy of the app (in the language just chosen) and closes this one.</summary>
    public static void Restart()
    {
        if (Environment.ProcessPath is { } exe)
        {
            Process.Start(new ProcessStartInfo(exe, $"{RestartArgument} {Environment.ProcessId.ToString(CultureInfo.InvariantCulture)}") { UseShellExecute = false });
        }

        (Application.Current.MainWindow as MainWindow)?.ExitApp();
    }

    /// <summary>Given to the new copy with the old copy's process id, which it waits for (the app runs once per user).</summary>
    public const string RestartArgument = "--after";

    /// <summary>The new copy: waits up to 10 seconds for the old one to exit.</summary>
    public static void WaitForPrevious(string[] args)
    {
        ArgumentNullException.ThrowIfNull(args);
        var at = Array.FindIndex(args, a => string.Equals(a, RestartArgument, StringComparison.OrdinalIgnoreCase));
        if (at < 0 || at + 1 >= args.Length || !int.TryParse(args[at + 1], NumberStyles.None, CultureInfo.InvariantCulture, out var pid))
        {
            return;
        }

        try
        {
            using var previous = Process.GetProcessById(pid);
            previous.WaitForExit(TimeSpan.FromSeconds(10));
        }
        catch (ArgumentException)
        {
            // Already gone.
        }
        catch (InvalidOperationException)
        {
            // Already gone.
        }
    }

    private static void OnLoaded(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement element)
        {
            Translate(element);
        }
    }

    private static void Translate(FrameworkElement element)
    {
        switch (element)
        {
            case TextBlock:
                Swap(element, TextBlock.TextProperty);
                break;
            case HeaderedItemsControl:
                Swap(element, HeaderedItemsControl.HeaderProperty);
                break;
            case HeaderedContentControl:
                Swap(element, HeaderedContentControl.HeaderProperty);
                Swap(element, ContentControl.ContentProperty);
                break;
            case Window window:
                Swap(element, Window.TitleProperty);
                if (L.Current.RightToLeft)
                {
                    window.FlowDirection = FlowDirection.RightToLeft;
                }

                break;
            case ContentControl:
                Swap(element, ContentControl.ContentProperty);
                break;
            case ListView { View: GridView grid }:
                foreach (var column in grid.Columns)
                {
                    Swap(column, GridViewColumn.HeaderProperty);
                }

                break;
        }

        Swap(element, FrameworkElement.ToolTipProperty);
        Swap(element, AutomationProperties.NameProperty);
        Swap(element, AutomationProperties.HelpTextProperty);
    }

    /// <summary>Replaces a fixed English text (set in XAML or a template) by its translation; leaves bound values alone.</summary>
    private static void Swap(DependencyObject target, DependencyProperty property)
    {
        var source = DependencyPropertyHelper.GetValueSource(target, property);
        if (source.IsExpression || source.BaseValueSource is not (BaseValueSource.Local or BaseValueSource.ParentTemplate)
            || BindingOperations.IsDataBound(target, property)
            || target.GetValue(property) is not string { Length: > 0 } english)
        {
            return;
        }

        var translated = L.T(english);
        if (!ReferenceEquals(translated, english) && translated != english)
        {
            target.SetValue(property, translated);
        }
    }
}
