using System.Globalization;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using CrioFire.Core;
using CrioFire.Core.Api;

namespace CrioFire.App.Pages;

/// <summary>
/// The last hour: connections CrioFire blocked, or everything that was allowed and why (your rule,
/// an automatic rule for Windows, loopback, or no rule), with allow and block for each.
/// </summary>
public partial class ActivityPage : UserControl, IPage
{
    private readonly AppModel _model;

    internal ActivityPage(AppModel model)
    {
        _model = model;
        InitializeComponent();
    }

    public string Title => "Activity";

    public string Subtitle { get; private set; } = "Connections CrioFire blocked in the last hour.";

    public FrameworkElement? Actions => null;

    public TimeSpan? AutoRefresh => TimeSpan.FromSeconds(5);

    private bool Allowed => ShowAllowed.IsChecked == true;

    public void Refresh()
    {
        if (_model.TakeShowAllowed())
        {
            ShowAllowed.IsChecked = true;
        }

        UpdateView();
        if (Allowed)
        {
            RefreshAllowed();
        }
        else
        {
            RefreshBlocked();
        }
    }

    private void UpdateView()
    {
        var allowed = Allowed;
        BlockedCard.Visibility = BlockedActions.Visibility = allowed ? Visibility.Collapsed : Visibility.Visible;
        AllowedCard.Visibility = AllowedActions.Visibility = LocalSwitch.Visibility = allowed ? Visibility.Visible : Visibility.Collapsed;
    }

    private void RefreshBlocked()
    {
        var selected = (Table.SelectedItem as ActivityRow)?.App;
        var events = Service.Call(new ApiRequest { Op = ApiOps.Events, Minutes = 60 }, out var error)?.Events;
        if (events is null)
        {
            Subtitle = error ?? "Could not read blocked connections.";
            Table.ItemsSource = null;
            Empty.Visibility = Visibility.Visible;
            return;
        }

        var chipFire = (Brush)FindResource("ChipFireBrush");
        var chipFireText = (Brush)FindResource("ChipFireTextBrush");
        var chipIce = (Brush)FindResource("ChipIceBrush");
        var chipIceText = (Brush)FindResource("ChipIceTextBrush");
        var rows = events
            .OrderByDescending(e => e.TimeUtc)
            .Take(300)
            .Select(e =>
            {
                var byMode = e.Kind == nameof(FilterKind.DefaultBlock);
                return new ActivityRow(
                    e.TimeUtc.ToLocalTime().ToString("HH:mm:ss", CultureInfo.CurrentCulture),
                    byMode ? "No rule yet" : e.Kind == nameof(FilterKind.Panic) ? "Panic: block all" : "Your rule",
                    e.Direction ?? "?",
                    e.Protocol,
                    e.Remote ?? "?",
                    KnownApps.DisplayName(e.App),
                    e.App,
                    byMode ? chipIce : chipFire,
                    byMode ? chipIceText : chipFireText);
            })
            .ToList();
        Table.ItemsSource = rows;
        Table.SelectedItem = rows.FirstOrDefault(r => r.App == selected);
        Empty.Visibility = rows.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        Subtitle = $"Connections CrioFire blocked in the last hour: {Fmt.Count(events.Count)}.";
    }

    private void RefreshAllowed()
    {
        var selected = AllowedTable.SelectedItem as AllowedActivityRow;
        var groups = Service.Call(new ApiRequest { Op = ApiOps.Allowed, Minutes = 60, IncludeLoopback = LocalSwitch.IsChecked == true }, out var error)?.Allowed;
        if (groups is null)
        {
            Subtitle = error ?? "Could not read allowed connections.";
            AllowedTable.ItemsSource = null;
            AllowedEmpty.Visibility = Visibility.Visible;
            return;
        }

        var chipIce = (Brush)FindResource("ChipIceBrush");
        var chipIceText = (Brush)FindResource("ChipIceTextBrush");
        var chipAuto = (Brush)FindResource("InsetBrush");
        var chipAutoText = (Brush)FindResource("Text2Brush");
        var c = CultureInfo.CurrentCulture;
        var rows = groups
            .Select(g =>
            {
                var automatic = AllowReasons.IsAutomatic(g.Reason);
                var (name, detail) = Who.Of(g.App, g.Service);
                var remote = g.Remote is null ? "?" : g.Port > 0 ? (g.Remote.Contains(':', StringComparison.Ordinal) ? $"[{g.Remote}]:{g.Port}" : $"{g.Remote}:{g.Port}") : g.Remote;
                return new AllowedActivityRow(
                    g.LastUtc.ToLocalTime().ToString("HH:mm", c),
                    AllowReasons.Label(g.Reason, g.Direction),
                    g.Direction ?? "?",
                    g.Protocol ?? "?",
                    remote,
                    Fmt.Count(g.Count),
                    name,
                    detail,
                    g.App,
                    g.Service,
                    automatic ? chipAuto : chipIce,
                    automatic ? chipAutoText : chipIceText);
            })
            .ToList();
        AllowedTable.ItemsSource = rows;
        AllowedTable.SelectedItem = selected is null ? null : rows.FirstOrDefault(r => r.App == selected.App && r.Service == selected.Service && r.Remote == selected.Remote);
        AllowedEmpty.Visibility = rows.Count == 0 ? Visibility.Visible : Visibility.Collapsed;

        var total = groups.Sum(g => g.Count);
        var automaticCount = groups.Where(g => AllowReasons.IsAutomatic(g.Reason)).Sum(g => g.Count);
        var who = groups.Select(g => (g.App?.ToUpperInvariant(), g.Service)).Distinct().Count();
        Subtitle = $"Allowed in the last hour: {Fmt.Count(total)} connections from {Fmt.Count(who)} programs and services, {Fmt.Count(automaticCount)} of them automatically.";
    }

    private string? SelectedApp()
    {
        if (Table.SelectedItem is ActivityRow { App: { } app })
        {
            return app;
        }

        _model.Say("Select a connection in the list first.");
        return null;
    }

    private void OnShow(object sender, RoutedEventArgs e) => Refresh();

    private void OnAllow(object sender, RoutedEventArgs e)
    {
        if (SelectedApp() is { } app)
        {
            _model.SetRule(app, "allow");
        }
    }

    private void OnAllowHour(object sender, RoutedEventArgs e)
    {
        if (SelectedApp() is { } app)
        {
            _model.SetRule(app, "allow", 60);
        }
    }

    private void OnBlock(object sender, RoutedEventArgs e)
    {
        if (SelectedApp() is { } app)
        {
            _model.SetRule(app, "block");
        }
    }

    private void OnAllowAllowed(object sender, RoutedEventArgs e) => DecideAllowed("allow");

    private void OnBlockAllowed(object sender, RoutedEventArgs e) => DecideAllowed("block");

    private void DecideAllowed(string action)
    {
        if (AllowedTable.SelectedItem is not AllowedActivityRow row)
        {
            _model.Say("Select a connection in the list first.");
            return;
        }

        if (Window.GetWindow(this) is { } owner)
        {
            _model.Decide(owner, row.App, row.Service, action);
        }
    }
}
