using System.Globalization;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using CrioFire.Core;
using CrioFire.Core.Api;

namespace CrioFire.App.Pages;

/// <summary>Connections CrioFire blocked in the last hour, with quick allow/block.</summary>
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

    public void Refresh()
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
                    byMode ? "No rule yet" : "Your rule",
                    e.Direction ?? "?",
                    e.Protocol,
                    e.Remote ?? "?",
                    Bars.Name(e.App),
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

    private string? SelectedApp()
    {
        if (Table.SelectedItem is ActivityRow { App: { } app })
        {
            return app;
        }

        _model.Say("Select a connection in the list first.");
        return null;
    }

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
}
