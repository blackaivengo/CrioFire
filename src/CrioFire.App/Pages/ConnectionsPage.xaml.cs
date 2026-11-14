using System.Globalization;
using System.Windows;
using System.Windows.Controls;
using CrioFire.Core;
using CrioFire.Core.Api;

namespace CrioFire.App.Pages;

/// <summary>
/// Live TCP and UDP connections with the program, and for svchost.exe the Windows services, that
/// own each; allow or block any of them. Reading needs no administrator rights. "Data used" shows
/// how much each program sent and received today or over the last 7 or 30 days.
/// </summary>
public partial class ConnectionsPage : UserControl, IPage
{
    private readonly AppModel _model;
    private (IReadOnlyList<LiveConnection> Connections, IReadOnlyDictionary<int, string[]> Services)? _loaded;
    private (UsageInfo? Usage, string? Error)? _usage;
    private string _period = "today";

    internal ConnectionsPage(AppModel model)
    {
        _model = model;
        InitializeComponent();
        RowMenu.Attach(Table, model, RowMenu.From);
        RowMenu.Attach(UsageTable, model, RowMenu.From);
    }

    private bool ShowingUsage => ShowUsage.IsChecked == true;

    public string Title => ShowingUsage ? L.T("Data used") : L.T("Live connections");

    public string Subtitle { get; private set; } = string.Empty;

    public FrameworkElement? Actions => null;

    public TimeSpan? AutoRefresh => ShowingUsage ? TimeSpan.FromSeconds(10) : TimeSpan.FromSeconds(3);

    public async Task LoadAsync()
    {
        if (ShowingUsage)
        {
            var period = _period;
            _usage = await Task.Run(() => ReadUsage(period));
        }
        else
        {
            _loaded = await Task.Run(Read);
        }
    }

    private static (UsageInfo? Usage, string? Error) ReadUsage(string period)
    {
        var response = Service.Call(new ApiRequest { Op = ApiOps.Usage, Period = period }, out var error);
        return (response?.Usage, response is null ? error : response.Usage is null ? L.T("This version of the CrioFire service does not count data yet.") : null);
    }

    private static (IReadOnlyList<LiveConnection> Connections, IReadOnlyDictionary<int, string[]> Services) Read() =>
        (ConnectionTable.Read(), WindowsServiceList.ByProcess(WindowsServiceList.Read()));

    public void Refresh()
    {
        var usage = ShowingUsage;
        LiveCard.Visibility = LiveActions.Visibility = usage ? Visibility.Collapsed : Visibility.Visible;
        UsageCard.Visibility = UsageActions.Visibility = PeriodGroup.Visibility = usage ? Visibility.Visible : Visibility.Collapsed;
        if (usage)
        {
            RefreshUsage();
            return;
        }

        var all = ShowAll.IsChecked == true;
        var selected = Table.SelectedItem as LiveRow;
        var (connections, services) = _loaded ?? Read();
        _loaded = null;
        var rows = connections
            .Where(c => all || c.Remote is not null)
            .OrderBy(c => c.ProcessPath is null)
            .ThenBy(c => c.ProcessPath, StringComparer.OrdinalIgnoreCase)
            .ThenBy(c => c.Local.Port)
            .Select(c => LiveRow.From(c, services))
            .ToList();
        Table.ItemsSource = rows;
        if (selected is not null)
        {
            Table.SelectedItem = rows.FirstOrDefault(r => r.ProcessId == selected.ProcessId && r.Local == selected.Local && r.Remote == selected.Remote);
        }

        var programs = rows.Select(r => r.ProcessId).Distinct().Count();
        Subtitle = L.T($"{Fmt.Count(rows.Count)} {(all ? "sockets" : "connections")} from {programs} programs. Updates every 3 seconds.");
    }

    private void RefreshUsage()
    {
        var (info, error) = _usage ?? ReadUsage(_period);
        _usage = null;
        var apps = info?.Apps ?? [];
        var total = Math.Max(apps.Sum(a => a.Total), 1);
        var culture = CultureInfo.CurrentCulture;
        var selected = (UsageTable.SelectedItem as UsageRow)?.App;
        var rows = apps.Select(a => UsageRow.From(a, total, culture)).ToList();
        UsageTable.ItemsSource = rows;
        UsageTable.SelectedItem = rows.FirstOrDefault(r => string.Equals(r.App, selected, StringComparison.OrdinalIgnoreCase));
        UsageTable.Visibility = rows.Count == 0 ? Visibility.Collapsed : Visibility.Visible;
        UsageEmpty.Visibility = rows.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        var when = _period switch { "7d" => L.T("in the last 7 days"), "30d" => L.T("in the last 30 days"), _ => L.T("today") };
        Subtitle = error ?? (info is null || rows.Count == 0
            ? L.T($"Nothing counted {when} yet.")
            : L.T($"{DataSize.Text(info.Sent, culture)} sent and {DataSize.Text(info.Received, culture)} received {when}, by {Fmt.Count(rows.Count)} programs. Traffic that stays on this PC is not counted."));
    }

    private void OnShow(object sender, RoutedEventArgs e) => _model.NotifyChanged();   // the window reloads this page and its title

    private void OnPeriod(object sender, RoutedEventArgs e)
    {
        if (sender is RadioButton { Tag: string period })
        {
            _period = period;
            _model.NotifyChanged();
        }
    }

    private void OnClearUsage(object sender, RoutedEventArgs e)
    {
        if (Window.GetWindow(this) is not { } owner
            || ChoiceDialog.Ask(owner, L.T("Clear the data counts?"), L.T("CrioFire forgets how much every program sent and received, for every day, and starts again from zero."),
                ["Clear counts", "Cancel"], defaultIndex: 1, danger: true) != 0)
        {
            return;
        }

        if (_model.Call(new ApiRequest { Op = ApiOps.ResetUsage }) is not null)
        {
            _model.Say(L.T("Data counts cleared."));
            _model.NotifyChanged();
        }
    }

    private void OnAllow(object sender, RoutedEventArgs e) => Decide("allow");

    private void OnBlock(object sender, RoutedEventArgs e) => Decide("block");

    private void Decide(string action)
    {
        if (Table.SelectedItem is not LiveRow row)
        {
            _model.Say(L.T("Select a connection in the list first."));
            return;
        }

        var app = row.ProcessId == 4 ? KnownApps.Kernel : row.Path;
        if (row.ProcessId != 4 && !System.IO.Path.IsPathRooted(app))
        {
            _model.Say(L.T("CrioFire can't see this program's path (it runs as another user). Open CrioFire as administrator to make a rule for it."));
            return;
        }

        if (Window.GetWindow(this) is { } owner)
        {
            _model.Decide(owner, app, row.Services.Length == 0 ? null : row.Services, action);
        }
    }
}
