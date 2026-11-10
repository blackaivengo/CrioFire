using System.Reflection;
using System.Windows;
using System.Windows.Controls;
using CrioFire.Core;

namespace CrioFire.App.Pages;

/// <summary>Appearance, recovery and version information.</summary>
public partial class SettingsPage : UserControl, IPage
{
    private readonly AppModel _model;

    internal SettingsPage(AppModel model)
    {
        _model = model;
        InitializeComponent();
    }

    public string Title => "Settings";

    public string Subtitle => "Appearance, recovery and version.";

    public FrameworkElement? Actions => null;

    public TimeSpan? AutoRefresh => null;

    public void Refresh()
    {
        ThemeSystem.IsChecked = ThemeManager.Choice == ThemeManager.System;
        ThemeLight.IsChecked = ThemeManager.Choice == ThemeManager.Light;
        ThemeDark.IsChecked = ThemeManager.Choice == ThemeManager.Dark;

        var app = typeof(SettingsPage).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? "?";
        var service = _model.Status is { } s ? s.Version : "not running";
        AboutText.Text =
            $"CrioFire Private Firewall by CrioSoft LLC. Free and open source under the GNU GPL v3.\n" +
            $"App {app} · Service {service}\n" +
            $"Blocked-connection log: {TrafficLog.DefaultPath}";
    }

    private void OnTheme(object sender, RoutedEventArgs e)
    {
        if (sender is RadioButton { Tag: string choice })
        {
            ThemeManager.Apply(choice);
        }
    }

    private void OnPanic(object sender, RoutedEventArgs e)
    {
        if (Window.GetWindow(this) is { } owner)
        {
            _model.Panic(owner);
        }
    }
}
