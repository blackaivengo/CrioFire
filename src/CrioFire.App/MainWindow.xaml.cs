using System.Globalization;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;
using CrioFire.Core;
using CrioFire.Core.Api;
using Microsoft.Win32;

namespace CrioFire.App;

public sealed record RuleRow(string Action, string Direction, string Program, string Until, string Kind, string? App);

public sealed record BlockedRow(string Time, string Why, string Direction, string Protocol, string Remote, string Program, string? App);

public sealed record ConnectionRow(string Protocol, string State, string Local, string Remote, int ProcessId, string Program);

/// <summary>
/// The CrioFire app: rules, recently blocked connections, live connections and the mode, all
/// through the criofire service, so it runs as a normal user. In Ask mode it also shows an alert
/// for each program the catch-all block stops.
/// </summary>
public partial class MainWindow : Window
{
    private readonly DispatcherTimer _poll = new() { Interval = TimeSpan.FromSeconds(2) };
    private readonly DispatcherTimer _connections = new() { Interval = TimeSpan.FromSeconds(3) };
    private readonly AlertTracker _alerts = new();
    private string _mode = "learning";
    private bool _settingModeBox;

    public MainWindow()
    {
        InitializeComponent();
        Loaded += (_, _) =>
        {
            Refresh();
            _poll.Tick += (_, _) => PollAlerts();
            _poll.Start();
            _connections.Tick += (_, _) => RefreshConnections();
        };
        Closed += (_, _) =>
        {
            _poll.Stop();
            _connections.Stop();
        };
    }

    private void OnRefresh(object sender, RoutedEventArgs e) => Refresh();

    private void OnShowListening(object sender, RoutedEventArgs e) => RefreshConnections();

    private void Refresh()
    {
        var status = Service.Call(new ApiRequest { Op = ApiOps.Status }, out var error);
        if (status?.Status is not { } info)
        {
            StatusText.Text = error ?? "CrioFire is not registered with the filtering engine yet.";
            return;
        }

        _mode = info.Mode;
        SelectMode(info.Mode);

        var rules = Service.Call(new ApiRequest { Op = ApiOps.List }, out error)?.Rules ?? [];
        RulesList.ItemsSource = rules
            .Where(r => r.Kind == nameof(FilterKind.AppRule))
            .GroupBy(r => (r.App, r.Action, r.Direction))   // one row per rule, not per IPv4/IPv6 filter
            .Select(g => g.First())
            .OrderBy(r => r.App, StringComparer.OrdinalIgnoreCase)
            .Select(r => new RuleRow(
                r.Action ?? "?",
                r.Direction ?? "?",
                r.App ?? r.Name,
                r.ExpiresUtc is DateTime t ? t.ToLocalTime().ToString("HH:mm", CultureInfo.CurrentCulture) : string.Empty,
                r.Kind,
                r.App))
            .ToList();

        var events = Service.Call(new ApiRequest { Op = ApiOps.Events, Minutes = 60 }, out _)?.Events ?? [];
        BlockedList.ItemsSource = events
            .OrderByDescending(e => e.TimeUtc)
            .Select(e => new BlockedRow(
                e.TimeUtc.ToLocalTime().ToString("HH:mm:ss", CultureInfo.CurrentCulture),
                e.Kind == nameof(FilterKind.DefaultBlock) ? "no rule (mode)" : "your rule",
                e.Direction ?? "?",
                e.Protocol,
                e.Remote ?? "?",
                e.App ?? "?",
                e.App))
            .ToList();

        StatusText.Text = error ?? $"Mode: {info.Mode}. {info.FilterCount} filters active. {events.Count} connections blocked in the last hour.";
    }

    private void SelectMode(string mode)
    {
        _settingModeBox = true;
        foreach (ComboBoxItem item in ModeBox.Items)
        {
            if ((string)item.Tag == mode)
            {
                ModeBox.SelectedItem = item;
            }
        }

        _settingModeBox = false;
    }

    private void OnModeChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_settingModeBox || ModeBox.SelectedItem is not ComboBoxItem { Tag: string mode } || mode == _mode)
        {
            return;
        }

        var previous = _mode;
        List<string>? running = null;
        if (mode != "learning")
        {
            var answer = MessageBox.Show(
                this,
                "Programs without an allow rule will no longer be able to connect out.\n\n" +
                "Also allow every program that is running right now? (Recommended the first time.)",
                "Switch mode",
                MessageBoxButton.YesNoCancel,
                MessageBoxImage.Question);
            if (answer == MessageBoxResult.Cancel)
            {
                SelectMode(previous);
                return;
            }

            if (answer == MessageBoxResult.Yes)
            {
                running = RunningPrograms();
            }
        }

        if (Service.Call(new ApiRequest { Op = ApiOps.SetMode, Mode = mode, Apps = running }, out var error) is null)
        {
            StatusText.Text = error;
            SelectMode(previous);
            return;
        }

        _mode = mode;
        if (mode != "learning" && new ConfirmModeWindow { Owner = this }.ShowDialog() != true)
        {
            Service.Call(new ApiRequest { Op = ApiOps.SetMode, Mode = previous }, out _);
            _mode = previous;
            StatusText.Text = $"Switched back to {previous}.";
        }

        Refresh();
    }

    private void OnAddAllow(object sender, RoutedEventArgs e) => AddRule("allow");

    private void OnAddBlock(object sender, RoutedEventArgs e) => AddRule("block");

    private void AddRule(string action)
    {
        var dialog = new OpenFileDialog { Filter = "Programs (*.exe)|*.exe", Title = $"Choose a program to {action}" };
        if (dialog.ShowDialog(this) == true)
        {
            SetRule(dialog.FileName, action, null);
        }
    }

    private void OnRemoveRule(object sender, RoutedEventArgs e)
    {
        if (RulesList.SelectedItem is RuleRow { App: { } app })
        {
            if (Service.Call(new ApiRequest { Op = ApiOps.RemoveRules, App = app }, out var error) is null)
            {
                StatusText.Text = error;
                return;
            }

            Refresh();
        }
    }

    private void OnAllowBlocked(object sender, RoutedEventArgs e)
    {
        if (BlockedList.SelectedItem is BlockedRow { App: { } app })
        {
            SetRule(app, "allow", null);
        }
    }

    private void OnBlockBlocked(object sender, RoutedEventArgs e)
    {
        if (BlockedList.SelectedItem is BlockedRow { App: { } app })
        {
            SetRule(app, "block", null);
        }
    }

    /// <summary>Creates a rule; returns false and shows the reason if the service refused.</summary>
    internal bool SetRule(string app, string action, int? expiresMinutes)
    {
        var result = Service.Call(new ApiRequest { Op = ApiOps.SetRule, App = app, Action = action, ExpiresMinutes = expiresMinutes }, out var error);
        if (result is null)
        {
            StatusText.Text = error;
            return false;
        }

        Refresh();
        return true;
    }

    private void OnTabChanged(object sender, SelectionChangedEventArgs e)
    {
        if (e.Source != Tabs)
        {
            return;
        }

        if (Tabs.SelectedIndex == 2)
        {
            RefreshConnections();
            _connections.Start();
        }
        else
        {
            _connections.Stop();
        }
    }

    private void RefreshConnections()
    {
        var showAll = ShowListeningBox.IsChecked == true;
        ConnectionsList.ItemsSource = ConnectionTable.Read()
            .Where(c => showAll || c.Remote is not null)
            .OrderBy(c => c.ProcessPath, StringComparer.OrdinalIgnoreCase)
            .Select(c => new ConnectionRow(c.ProtocolName, c.State, c.Local.ToString(), c.Remote?.ToString() ?? string.Empty, c.ProcessId, c.ProcessPath ?? "?"))
            .ToList();
    }

    /// <summary>In Ask mode, show an alert for each program the catch-all block stopped.</summary>
    private void PollAlerts()
    {
        if (_mode != "ask")
        {
            return;
        }

        var events = Service.Call(new ApiRequest { Op = ApiOps.Events, Minutes = 1 }, out _)?.Events;
        var rules = Service.Call(new ApiRequest { Op = ApiOps.List }, out _)?.Rules;
        if (events is null || rules is null)
        {
            return;
        }

        foreach (var alert in _alerts.NewAlerts(events, rules))
        {
            var window = new AlertWindow(alert);
            window.Closed += (_, _) =>
            {
                var app = alert.App!;
                switch (window.Choice)
                {
                    case AlertChoice.Allow:
                        SetRule(app, "allow", null);
                        _alerts.Decided(app);
                        break;
                    case AlertChoice.AllowOneHour:
                        SetRule(app, "allow", 60);
                        _alerts.Decided(app);
                        break;
                    case AlertChoice.Block:
                        SetRule(app, "block", null);
                        _alerts.Decided(app);
                        break;
                    default:
                        _alerts.Dismissed(app);
                        break;
                }
            };
            window.Show();
        }
    }

    private static List<string> RunningPrograms()
    {
        var paths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var process in System.Diagnostics.Process.GetProcesses())
        {
            using (process)
            {
                try
                {
                    if (process.MainModule?.FileName is { Length: > 0 } path)
                    {
                        paths.Add(path);
                    }
                }
                catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException or NotSupportedException)
                {
                }
            }
        }

        return [.. paths];
    }
}

/// <summary>Short-lived calls to the criofire service; errors become a message for the status line.</summary>
internal static class Service
{
    public static ApiResponse? Call(ApiRequest request, out string? error)
    {
        try
        {
            using var client = CrioFireClient.TryConnect(timeoutMs: 500);
            if (client is null)
            {
                error = "The CrioFire service is not running. Start it with 'sc start criofire' from an administrator prompt.";
                return null;
            }

            var response = client.Send(request);
            error = response.Ok ? null : response.Error;
            return response.Ok ? response : null;
        }
        catch (IOException ex)
        {
            error = $"Lost the connection to the CrioFire service: {ex.Message}";
            return null;
        }
    }
}
