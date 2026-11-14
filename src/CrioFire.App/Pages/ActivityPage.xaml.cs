using System.Globalization;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Threading;
using CrioFire.Core;
using CrioFire.Core.Api;

namespace CrioFire.App.Pages;

/// <summary>
/// Every blocked and allowed connection the service recorded, filtered (kind, time, direction,
/// reason, program, text) and paged; select one or many to allow or block them, and see
/// everything known about the selected one: program, destination, port, reason and rules.
/// </summary>
public partial class ActivityPage : UserControl, IPage
{
    private const int PageSize = 100;

    private readonly AppModel _model;
    private readonly DispatcherTimer _searchDelay = new() { Interval = TimeSpan.FromMilliseconds(350) };
    private int _offset;
    private string? _app;
    private string? _service;
    private bool _quiet;
    private TrafficRow? _shown;

    internal ActivityPage(AppModel model)
    {
        _model = model;
        InitializeComponent();
        RowMenu.Attach(Table, model, RowMenu.From, Selected);
        _searchDelay.Tick += (_, _) =>
        {
            _searchDelay.Stop();
            _offset = 0;
            _model.NotifyChanged();
        };
    }

    public string Title => L.T("Activity");

    public string Subtitle { get; private set; } = L.T("Everything CrioFire blocked or allowed.");

    public FrameworkElement? Actions => null;

    /// <summary>No timer: reloading would jump the list back to the top while you read it. There is a Refresh button.</summary>
    public TimeSpan? AutoRefresh => null;

    private string Kind => KindAllowed.IsChecked == true ? "allowed" : KindAll.IsChecked == true ? "all" : "blocked";

    private int Minutes => WindowHour.IsChecked == true ? 60 : WindowWeek.IsChecked == true ? 10080 : WindowMonth.IsChecked == true ? 43200 : 1440;

    private string WindowText => Minutes switch { 60 => L.T("hour"), 10080 => L.T("7 days"), 43200 => L.T("30 days"), _ => L.T("24 hours") };

    private string? WhyGroup => new[] { WhyMine, WhyNoRule, WhyAuto, WhyLocal, WhyPanic }.FirstOrDefault(r => r.IsChecked == true)?.Tag as string;

    private string? DirectionFilter => DirOut.IsChecked == true ? "out" : DirIn.IsChecked == true ? "in" : null;

    private (ApiRequest Request, TrafficPage? Page, string? Error)? _loaded;

    /// <summary>Asks the service for the page of traffic off the UI thread; Refresh shows it.</summary>
    public async Task LoadAsync()
    {
        TakeQuery();
        var request = BuildRequest();
        _loaded = await Task.Run(() => Read(request));
    }

    private static (ApiRequest Request, TrafficPage? Page, string? Error) Read(ApiRequest request)
    {
        var page = Service.Call(request, out var error)?.Traffic;
        return (request, page, error);
    }

    private void TakeQuery()
    {
        if (_model.TakeActivityQuery() is { } query)
        {
            Apply(query);
        }
    }

    public void Refresh()
    {
        TakeQuery();
        LocalSwitch.Visibility = Kind == "blocked" ? Visibility.Collapsed : Visibility.Visible;
        var request = BuildRequest();
        var data = _loaded is { } loaded && loaded.Request == request ? loaded : Read(request);
        _loaded = null;
        var page = data.Page;
        var error = data.Error;

        UpdateScope();
        if (page is null)
        {
            Subtitle = error ?? L.T("Could not read the traffic history.");
            Table.ItemsSource = null;
            Empty.Text = L.T("The traffic history comes from the CrioFire service, which records every blocked and allowed connection while it runs.");
            Empty.Visibility = Visibility.Visible;
            PageText.Text = string.Empty;
            PrevButton.IsEnabled = NextButton.IsEnabled = false;
            ShowDetails(null);
            return;
        }

        _offset = page.Offset;
        var keep = Table.SelectedItems.OfType<TrafficRow>().Select(r => r.Key).ToHashSet();
        var rows = page.Items.Select(ToRow).ToList();
        _quiet = true;
        Table.ItemsSource = rows;
        foreach (var row in rows.Where(r => keep.Contains(r.Key)))
        {
            Table.SelectedItems.Add(row);
        }

        _quiet = false;

        Empty.Visibility = rows.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        Empty.Text = L.T($"Nothing {(Kind == "allowed" ? L.T("allowed") : Kind == "blocked" ? L.T("blocked") : L.T("recorded"))} in the last {WindowText} matches these filters.");
        PageText.Text = page.Total == 0 ? string.Empty
            : $"Rows {Fmt.Count(page.Offset + 1)}–{Fmt.Count(page.Offset + rows.Count)} of {Fmt.Count(page.Total)}";
        PrevButton.IsEnabled = page.Offset > 0;
        NextButton.IsEnabled = page.Offset + rows.Count < page.Total;

        var what = Kind switch { "allowed" => L.T("Allowed"), "all" => L.T("Blocked and allowed"), _ => L.T("Blocked") };
        Subtitle = L.T($"{what} in the last {WindowText}: {Fmt.Count(page.Connections)} connections in {Fmt.Count(page.Total)} rows.");
        UpdateSelection();
    }

    private ApiRequest BuildRequest()
    {
        var search = SearchBox.Text.Trim();
        return new ApiRequest
        {
            Op = ApiOps.Traffic,
            TrafficKind = Kind,
            Minutes = Minutes,
            Search = search.Length == 0 ? null : search,
            Why = WhyGroup,
            Direction = DirectionFilter,
            App = _app,
            Service = _service,
            IncludeLoopback = LocalSwitch.IsChecked == true,
            Sort = SortCount.IsChecked == true ? "count" : "recent",
            Offset = _offset,
            Limit = PageSize,
        };
    }

    /// <summary>Sets the filters a dashboard panel asked for.</summary>
    private void Apply(ActivityQuery q)
    {
        KindAllowed.IsChecked = q.Kind == "allowed";
        KindAll.IsChecked = q.Kind == "all";
        KindBlocked.IsChecked = q.Kind is not ("allowed" or "all");
        WindowHour.IsChecked = q.Minutes <= 60;
        WindowDay.IsChecked = q.Minutes is > 60 and <= 1440;
        WindowWeek.IsChecked = q.Minutes is > 1440 and <= 10080;
        WindowMonth.IsChecked = q.Minutes > 10080;
        foreach (var r in new[] { WhyMine, WhyNoRule, WhyAuto, WhyLocal, WhyPanic })
        {
            r.IsChecked = q.Why is not null && (string)r.Tag == q.Why;
        }

        WhyAll.IsChecked = q.Why is null;
        DirAny.IsChecked = true;
        SortCount.IsChecked = q.Sort == "count";
        SortRecent.IsChecked = q.Sort != "count";
        _app = q.App;
        _service = q.Service;
        _searchDelay.Stop();
        SearchBox.TextChanged -= OnSearchChanged;
        SearchBox.Text = q.Search ?? string.Empty;
        SearchBox.TextChanged += OnSearchChanged;
        _offset = 0;
        Table.SelectedItems.Clear();
    }

    private TrafficRow ToRow(TrafficItem i)
    {
        var c = CultureInfo.CurrentCulture;
        var last = i.LastUtc.ToLocalTime();
        var time = Minutes <= 1440 ? last.ToString("HH:mm:ss", c) : last.ToString("MMM d HH:mm", c);
        var automatic = i.Allowed && AllowReasons.IsAutomatic(i.Why);
        var (chip, chipText) = !i.Allowed
            ? (i.Why == nameof(FilterKind.DefaultBlock) ? ("ChipIceBrush", "ChipIceTextBrush") : ("ChipFireBrush", "ChipFireTextBrush"))
            : automatic ? ("InsetBrush", "Text2Brush") : ("ChipIceBrush", "ChipIceTextBrush");
        var (program, detail) = Who.Of(i.App, i.Service);
        var portName = i.Port > 0 ? $"{i.Protocol} {i.Port}" + (NetworkFacts.PortName(i.Port) is { } name ? $" · {name}" : string.Empty) : i.Protocol ?? string.Empty;
        return new TrafficRow(
            i,
            time,
            Fmt.Count(i.Count),
            (i.Allowed ? string.Empty : L.T("Blocked: ")) + i.WhyLabel,
            i.Direction ?? "?",
            Endpoint(i.Remote, i.Allowed || i.Direction == "out" ? i.Port : 0),
            portName,
            program,
            detail,
            (Brush)FindResource(chip),
            (Brush)FindResource(chipText));
    }

    private static string Endpoint(string? address, int port)
    {
        if (string.IsNullOrEmpty(address))
        {
            return "?";
        }

        if (port <= 0)
        {
            return address;
        }

        return address.Contains(':', StringComparison.Ordinal) ? $"[{address}]:{port}" : $"{address}:{port}";
    }

    private List<TrafficItem> Selected() => Table.SelectedItems.OfType<TrafficRow>().Select(r => r.Item).ToList();

    private void UpdateSelection()
    {
        var selected = Table.SelectedItems.OfType<TrafficRow>().ToList();
        SelectionText.Text = selected.Count switch
        {
            0 => L.T("Ctrl or Shift selects several rows."),
            1 => L.T("1 row selected."),
            _ => L.T($"{selected.Count} rows selected: Allow and Block apply to all of them."),
        };
        ShowDetails(Table.SelectedItem as TrafficRow ?? selected.FirstOrDefault());
    }

    private void UpdateScope()
    {
        var scope = _service is not null ? L.T($"Service: {_service}") : _app is not null ? L.T($"Program: {KnownApps.DisplayName(_app)}") : null;
        ScopeChip.Visibility = scope is null ? Visibility.Collapsed : Visibility.Visible;
        ScopeText.Text = scope ?? string.Empty;
        ScopeChip.ToolTip = _app;
    }

    // ---- details ----

    private void ShowDetails(TrafficRow? row)
    {
        _shown = row;
        DetailEmpty.Visibility = row is null ? Visibility.Visible : Visibility.Collapsed;
        DetailPanel.Visibility = row is null ? Visibility.Collapsed : Visibility.Visible;
        if (row is null)
        {
            return;
        }

        var i = row.Item;
        DetailTitle.Text = row.Program;
        DetailPath.Text = row.Detail;
        DetailWhy.Text = row.Why;
        DetailChip.Background = row.ChipBrush;
        DetailWhy.Foreground = row.ChipTextBrush;
        DetailFacts.ItemsSource = ConnectionFacts.For(Target(i), _model);
        OnlyThisButton.Content = i.Service is not null && !i.Service.Contains(',', StringComparison.Ordinal) ? L.T("Only this service") : L.T("Only this program");
        OnlyThisButton.IsEnabled = i.App is not null;
        OpenFolderButton.IsEnabled = i.App is not null && File.Exists(i.App);

        if (ConnectionFacts.NeedsLookup(i.Remote))
        {
            LookUpHost(i.Remote!);
        }
    }

    private static MenuTarget Target(TrafficItem i) => new(i.App, i.Service, i.Remote, i.Port, i);

    private async void LookUpHost(string address)
    {
        await ConnectionFacts.LookUpAsync(address);
        if (_shown?.Item.Remote == address)
        {
            DetailFacts.ItemsSource = ConnectionFacts.For(Target(_shown.Item), _model);
        }
    }

    // ---- events ----

    private void OnFilterChanged(object sender, RoutedEventArgs e)
    {
        _offset = 0;
        _model.NotifyChanged();
    }

    private void OnSearchChanged(object sender, TextChangedEventArgs e)
    {
        _searchDelay.Stop();
        _searchDelay.Start();
    }

    private void OnClearScope(object sender, RoutedEventArgs e)
    {
        _app = null;
        _service = null;
        _offset = 0;
        _model.NotifyChanged();
    }

    private void OnSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (!_quiet)
        {
            UpdateSelection();
        }
    }

    private void OnSelectPage(object sender, RoutedEventArgs e) => Table.SelectAll();

    private void OnRefresh(object sender, RoutedEventArgs e) => _model.NotifyChanged();

    private void OnPrev(object sender, RoutedEventArgs e)
    {
        _offset = Math.Max(0, _offset - PageSize);
        _model.NotifyChanged();
    }

    private void OnNext(object sender, RoutedEventArgs e)
    {
        _offset += PageSize;
        _model.NotifyChanged();
    }

    private void OnAllow(object sender, RoutedEventArgs e) => Act("allow", null);

    private void OnAllowHour(object sender, RoutedEventArgs e) => Act("allow", 60);

    private void OnBlock(object sender, RoutedEventArgs e) => Act("block", null);

    private void Act(string action, int? minutes)
    {
        if (Window.GetWindow(this) is { } owner)
        {
            _model.ApplyToMany(owner, Selected(), action, minutes);
        }
    }

    private void OnOnlyThis(object sender, RoutedEventArgs e)
    {
        if (_shown?.Item is not { App: { } app } item)
        {
            return;
        }

        var services = (item.Service ?? string.Empty).Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        _service = services.Length == 1 ? services[0] : null;
        _app = _service is null ? app : null;
        _offset = 0;
        Table.SelectedItems.Clear();
        _model.NotifyChanged();
    }

    private void OnOpenFolder(object sender, RoutedEventArgs e) => RowMenu.OpenFolder(_shown?.Item.App);

    private void OnCopy(object sender, RoutedEventArgs e)
    {
        if (_shown is { } row)
        {
            RowMenu.Copy(_model, ConnectionFacts.AsText($"{row.Program} · {row.Why}", row.Detail, ConnectionFacts.For(Target(row.Item), _model)));
        }
    }
}
