using System.Globalization;
using System.Reflection;
using System.Windows;
using System.Windows.Controls;
using CrioFire.Core;
using CrioFire.Core.Api;

namespace CrioFire.App.Pages;

/// <summary>Appearance, startup, recovery, networks, license, protection, history, backups and version.</summary>
public partial class SettingsPage : UserControl, IPage
{
    private readonly AppModel _model;

    internal SettingsPage(AppModel model)
    {
        _model = model;
        InitializeComponent();
    }

    public string Title => "Settings";

    public string Subtitle => "Appearance, startup, recovery, history and version.";

    public FrameworkElement? Actions => null;

    public TimeSpan? AutoRefresh => null;

    private IReadOnlyList<BackupInfo>? _backups;
    private LicenseStatus? _license;
    private CrioFire.Core.Management.ManagementInfo? _management;
    private IReadOnlyList<ConnectedNetwork>? _networks;
    private LogsInfo? _logs;
    private bool _logsLoaded;

    public async Task LoadAsync()
    {
        (_backups, _license, _management, _networks, _logs) = await Task.Run(() => (AppModel.Backups(), AppModel.License(), AppModel.Management(), NetworkList.Current(), AppModel.Logs()));
        _logsLoaded = true;
    }

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
            $"Blocked-connection log: {TrafficLog.DefaultPath}" +
            ManagedText(_management ?? AppModel.Management());
        _management = null;

        var networks = _networks ?? NetworkList.Current();
        _networks = null;
        NetworksText.Text = networks.Count == 0
            ? "Windows does not report a network right now."
            : $"This PC is on {ConnectedNetworks.Describe(networks)}.";

        ShowLicense(_license ?? AppModel.License());
        _license = null;
        ProtectionSwitch.IsChecked = _model.Status?.RequireAdmin == true;
        ProtectionSwitch.IsEnabled = _model.Status is not null;
        ShowBackups(_backups ?? AppModel.Backups());
        _backups = null;
        ShowLogs(_logsLoaded ? _logs : AppModel.Logs());
        _logs = null;
        _logsLoaded = false;

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

    private static string ManagedText(CrioFire.Core.Management.ManagementInfo? info) => info is null
        ? string.Empty
        : $"\nManaged by the CrioFire Server {info.Url}"
            + (info.LastCheckinUtc is { } last ? $", last check-in {last.ToLocalTime():g}" : ", not checked in yet")
            + (info.LastError is { } error ? $". Last problem: {error}" : ".")
            + (info.Policy is { } p
                ? $"\nOrganization policy: {p.Name}, {p.Rules} rules"
                    + (p.Mode is null ? string.Empty : $", mode {p.Mode}")
                    + (p.AllowUserRules ? ", your own rules allowed" : ", your own rules not allowed")
                    + (p.RequireAdmin ? ", tamper protection required." : ".")
                : string.Empty);

    private void ShowLicense(LicenseStatus? status)
    {
        LicenseText.Text = status?.Message ?? "The license is shown when the CrioFire service is running.";
        LicenseText.SetResourceReference(TextBlock.ForegroundProperty,
            status?.State is LicenseStates.Expired or LicenseStates.Invalid or LicenseStates.Expiring ? "FireBrush" : "TextBrush");
        LicenseRemove.Visibility = status is { State: not LicenseStates.None } ? Visibility.Visible : Visibility.Collapsed;
    }

    private void OnNetworkSettings(object sender, RoutedEventArgs e)
    {
        try
        {
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("ms-settings:network-status") { UseShellExecute = true })?.Dispose();
        }
        catch (System.ComponentModel.Win32Exception)
        {
            // No Settings app (Windows Server core): nothing to open.
        }
    }

    private void OnEnterLicense(object sender, RoutedEventArgs e)
    {
        var key = LicenseKeys.Clean(LicenseKeyBox.Text);
        if (key.Length == 0)
        {
            _model.Say("Paste the license key from your license email first.");
            return;
        }

        if (_model.SetLicense(key) is { } status)
        {
            LicenseKeyBox.Clear();
            ShowLicense(status);
        }
    }

    private void OnRemoveLicense(object sender, RoutedEventArgs e)
    {
        if (Window.GetWindow(this) is { } owner
            && ChoiceDialog.Ask(owner, "Remove the license key?", "CrioFire goes back to free use. Keep the key if this PC belongs to a business with more than 3 computers.", ["Remove", "Cancel"], defaultIndex: 1) == 0
            && _model.SetLicense(string.Empty) is { } status)
        {
            ShowLicense(status);
        }
    }

    private void ShowLogs(LogsInfo? logs)
    {
        var settings = logs?.Settings ?? new LogSettings();
        foreach (var choice in KeepChoices.Children.OfType<RadioButton>())
        {
            choice.IsChecked = choice.Tag as string == settings.KeepDays.ToString(CultureInfo.InvariantCulture);
        }

        foreach (var choice in SizeChoices.Children.OfType<RadioButton>())
        {
            choice.IsChecked = choice.Tag as string == settings.MaxMegabytes.ToString(CultureInfo.InvariantCulture);
        }

        RecordAllowedSwitch.IsChecked = settings.RecordAllowed;
        KeepChoices.IsEnabled = SizeChoices.IsEnabled = RecordAllowedSwitch.IsEnabled = ClearLogsButton.IsEnabled = logs is not null;
        var culture = CultureInfo.CurrentCulture;
        LogsText.Text = logs is null
            ? "The CrioFire service is not running, or is too old to change this."
            : $"Keeping {LogSettings.KeepText(settings.KeepDays)}, up to {settings.MaxMegabytes} MB per log. Now: blocked {DataSize.Text(logs.BlockedBytes, culture)}, allowed {DataSize.Text(logs.AllowedBytes, culture)}"
              + (logs.OldestUtc is { } oldest ? $", the oldest from {oldest.ToLocalTime().ToString("d", culture)}." : ", nothing recorded yet.");
    }

    private void ChangeLogs(Func<LogSettings, LogSettings> change)
    {
        var current = AppModel.Logs()?.Settings ?? new LogSettings();
        _model.SetLogs(change(current));
        ShowLogs(AppModel.Logs());   // what is really in force, also when it was not approved
    }

    private void OnLogKeep(object sender, RoutedEventArgs e)
    {
        if (sender is RadioButton { Tag: string tag } && int.TryParse(tag, CultureInfo.InvariantCulture, out var days))
        {
            ChangeLogs(s => s with { KeepDays = days });
        }
    }

    private void OnLogSize(object sender, RoutedEventArgs e)
    {
        if (sender is RadioButton { Tag: string tag } && int.TryParse(tag, CultureInfo.InvariantCulture, out var mb))
        {
            ChangeLogs(s => s with { MaxMegabytes = mb });
        }
    }

    private void OnRecordAllowed(object sender, RoutedEventArgs e)
    {
        var on = RecordAllowedSwitch.IsChecked == true;
        ChangeLogs(s => s with { RecordAllowed = on });
    }

    private void OnClearLogs(object sender, RoutedEventArgs e)
    {
        if (Window.GetWindow(this) is not { } owner
            || ChoiceDialog.Ask(owner, "Clear the connection history?", "CrioFire forgets every blocked and allowed connection recorded so far. The Dashboard, Traffic and Reports start again from now. Your rules stay as they are.",
                ["Clear history", "Cancel"], defaultIndex: 1, danger: true) != 0)
        {
            return;
        }

        _model.ClearLogs();
        ShowLogs(AppModel.Logs());
    }

    private void OnProtection(object sender, RoutedEventArgs e)
    {
        var on = ProtectionSwitch.IsChecked == true;
        if (!_model.SetProtection(on))
        {
            ProtectionSwitch.IsChecked = !on;   // not approved, or it failed: show what is really in force
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
