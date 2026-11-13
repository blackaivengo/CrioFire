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

    public string Subtitle => "Appearance, startup, recovery and version.";

    public FrameworkElement? Actions => null;

    public TimeSpan? AutoRefresh => null;

    private IReadOnlyList<BackupInfo>? _backups;

    public async Task LoadAsync() => _backups = await Task.Run(AppModel.Backups);

    public void Refresh()
    {
        ThemeSystem.IsChecked = ThemeManager.Choice == ThemeManager.System;
        ThemeLight.IsChecked = ThemeManager.Choice == ThemeManager.Light;
        ThemeDark.IsChecked = ThemeManager.Choice == ThemeManager.Dark;
        AutostartSwitch.IsChecked = Autostart.IsEnabled;
        CloseToTraySwitch.IsChecked = Prefs.Current.CloseToTray;

        var app = typeof(SettingsPage).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? "?";
        var service = _model.Status is { } s ? s.Version : "not running";
        AboutText.Text =
            $"CrioFire Private Firewall by CrioSoft LLC.\n" +
            $"Free for personal use, non-profits, schools, government, and businesses on up to 3 computers. " +
            $"Other business use needs a CrioSoft commercial license (see LICENSING.md).\n" +
            $"App {app} · Service {service}\n" +
            $"Blocked-connection log: {TrafficLog.DefaultPath}";

        ShowBackups(_backups ?? AppModel.Backups());
        _backups = null;

        // The same panic choices as the sidebar, without "remove all rules": nothing here deletes a rule.
        var panic = _model.PanicMode;
        var online = _model.Status is not null;
        PanicState.Text = !online ? "The CrioFire service is not running, so panic is not available here. Use the command line from an administrator prompt."
            : panic switch
            {
                "allow" => "Panic is on: everything is allowed and your rules are paused.",
                "block" => "Panic is on: all network traffic is blocked. Your rules are kept.",
                _ => "Panic is off. Your rules apply.",
            };
        ResumeButton.Visibility = online && panic != "off" ? Visibility.Visible : Visibility.Collapsed;
        AllowAllButton.Visibility = online && panic != "allow" ? Visibility.Visible : Visibility.Collapsed;
        BlockAllButton.Visibility = online && panic != "block" ? Visibility.Visible : Visibility.Collapsed;
    }

    private void OnTheme(object sender, RoutedEventArgs e)
    {
        if (sender is RadioButton { Tag: string choice })
        {
            ThemeManager.Apply(choice);
        }
    }

    private void OnAutostart(object sender, RoutedEventArgs e)
    {
        var enable = AutostartSwitch.IsChecked == true;
        if (!Autostart.Set(enable))
        {
            _model.Say("Could not change the Windows startup setting.");
        }

        AutostartSwitch.IsChecked = Autostart.IsEnabled;
    }

    private void OnCloseToTray(object sender, RoutedEventArgs e)
    {
        Prefs.Current.CloseToTray = CloseToTraySwitch.IsChecked == true;
        Prefs.Save();
    }

    private void ShowBackups(IReadOnlyList<BackupInfo> backups)
    {
        BackupList.Children.Clear();
        if (backups.Count == 0)
        {
            BackupList.Children.Add(new TextBlock { Text = "No backups yet.", FontSize = 13 });
            return;
        }

        foreach (var backup in backups.Take(10))
        {
            var row = new DockPanel { Margin = new Thickness(0, 0, 0, 8) };
            var restore = new Button { Content = "Restore...", Style = (Style)FindResource("GhostButton"), MinHeight = 32 };
            restore.Click += (_, _) => Restore(backup);
            DockPanel.SetDock(restore, Dock.Right);
            row.Children.Add(restore);
            row.Children.Add(new TextBlock
            {
                Text = $"{backup.CreatedUtc.ToLocalTime():g} · {backup.Rules} rules · {ReasonText(backup.Reason)}",
                FontSize = 13,
                VerticalAlignment = VerticalAlignment.Center,
            });
            BackupList.Children.Add(row);
        }
    }

    private static string ReasonText(string reason) => reason switch
    {
        _ when reason.StartsWith("auto", StringComparison.Ordinal) => "saved automatically",
        _ when reason.StartsWith("before-import", StringComparison.Ordinal) => "before an import",
        _ when reason.StartsWith("before-remove-all", StringComparison.Ordinal) => "before removing all rules",
        _ => reason,
    };

    private void Restore(BackupInfo backup)
    {
        if (Window.GetWindow(this) is not { } owner || _model.PlanRestore(backup.Name) is not { } plan)
        {
            return;
        }

        var mode = plan.ModeChange is { } m ? $" The mode goes back to {m}." : string.Empty;
        var message = $"This puts your rules back as they were on {backup.CreatedUtc.ToLocalTime():g}: "
            + $"{plan.Add} added, {plan.Change} changed, {plan.Remove} removed.{mode}"
            + (plan.Missing.Count > 0 ? $" {plan.Missing.Count} program(s) are no longer on this PC and are skipped." : string.Empty)
            + " Your rules from now are saved as a backup first.";
        if (ChoiceDialog.Ask(owner, "Restore this backup?", message, ["Restore", "Cancel"], defaultIndex: 1) == 0)
        {
            _model.RestoreBackup(backup.Name);
        }
    }

    private void OnResume(object sender, RoutedEventArgs e) => _model.Resume();

    private void OnAllowAll(object sender, RoutedEventArgs e) => AskThenPanic(
        "allow",
        "Allow everything?",
        "Every program may connect, in and out, until you resume. Your rules, mode and automatic rules are paused, not deleted.",
        "Allow everything",
        danger: false);

    private void OnBlockAll(object sender, RoutedEventArgs e) => AskThenPanic(
        "block",
        "Block all network traffic?",
        "Like pulling the network cable: no new connection in or out until you resume. Programs on this PC can still talk to each other. Your rules are kept.",
        "Block everything",
        danger: true);

    /// <summary>One click on a settings page is easy to make by accident, so panic is confirmed here.</summary>
    private void AskThenPanic(string action, string title, string message, string yes, bool danger)
    {
        if (Window.GetWindow(this) is not { } owner)
        {
            return;
        }

        if (ChoiceDialog.Ask(owner, title, message, [yes, "Cancel"], defaultIndex: 1, danger: danger) == 0)
        {
            _model.Panic(action);
        }
    }
}
