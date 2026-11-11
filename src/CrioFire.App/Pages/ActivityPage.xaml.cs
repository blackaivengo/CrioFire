using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Threading;
using System.Net;
using System.Net.Sockets;
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
    private readonly Dictionary<string, string> _hostNames = [];
    private int _offset;
    private string? _app;
    private string? _service;
    private bool _quiet;
    private TrafficRow? _shown;

    internal ActivityPage(AppModel model)
    {
        _model = model;
        InitializeComponent();
        _searchDelay.Tick += (_, _) =>
        {
            _searchDelay.Stop();
            _offset = 0;
            _model.NotifyChanged();
        };
    }

    public string Title => "Activity";

    public string Subtitle { get; private set; } = "Everything CrioFire blocked or allowed.";

    public FrameworkElement? Actions => null;

    /// <summary>No timer: reloading would jump the list back to the top while you read it. There is a Refresh button.</summary>
    public TimeSpan? AutoRefresh => null;

    private string Kind => KindAllowed.IsChecked == true ? "allowed" : KindAll.IsChecked == true ? "all" : "blocked";

    private int Minutes => WindowHour.IsChecked == true ? 60 : WindowWeek.IsChecked == true ? 10080 : WindowMonth.IsChecked == true ? 43200 : 1440;

    private string WindowText => Minutes switch { 60 => "hour", 10080 => "7 days", 43200 => "30 days", _ => "24 hours" };

    private string? WhyGroup => new[] { WhyMine, WhyNoRule, WhyAuto, WhyLocal, WhyPanic }.FirstOrDefault(r => r.IsChecked == true)?.Tag as string;

    private string? DirectionFilter => DirOut.IsChecked == true ? "out" : DirIn.IsChecked == true ? "in" : null;

    public void Refresh()
    {
        if (_model.TakeActivityQuery() is { } query)
        {
            Apply(query);
        }

        LocalSwitch.Visibility = Kind == "blocked" ? Visibility.Collapsed : Visibility.Visible;
        var search = SearchBox.Text.Trim();
        var page = Service.Call(new ApiRequest
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
        }, out var error)?.Traffic;

        UpdateScope();
        if (page is null)
        {
            Subtitle = error ?? "Could not read the traffic history.";
            Table.ItemsSource = null;
            Empty.Text = "The traffic history comes from the CrioFire service, which records every blocked and allowed connection while it runs.";
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
        Empty.Text = $"Nothing {(Kind == "allowed" ? "allowed" : Kind == "blocked" ? "blocked" : "recorded")} in the last {WindowText} matches these filters.";
        PageText.Text = page.Total == 0 ? string.Empty
            : $"Rows {Fmt.Count(page.Offset + 1)}–{Fmt.Count(page.Offset + rows.Count)} of {Fmt.Count(page.Total)}";
        PrevButton.IsEnabled = page.Offset > 0;
        NextButton.IsEnabled = page.Offset + rows.Count < page.Total;

        var what = Kind switch { "allowed" => "Allowed", "all" => "Blocked and allowed", _ => "Blocked" };
        Subtitle = $"{what} in the last {WindowText}: {Fmt.Count(page.Connections)} connections in {Fmt.Count(page.Total)} rows.";
        UpdateSelection();
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
            (i.Allowed ? string.Empty : "Blocked: ") + i.WhyLabel,
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
            0 => "Ctrl or Shift selects several rows.",
            1 => "1 row selected.",
            _ => $"{selected.Count} rows selected: Allow and Block apply to all of them.",
        };
        ShowDetails(Table.SelectedItem as TrafficRow ?? selected.FirstOrDefault());
    }

    private void UpdateScope()
    {
        var scope = _service is not null ? $"Service: {_service}" : _app is not null ? $"Program: {KnownApps.DisplayName(_app)}" : null;
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
        DetailFacts.ItemsSource = Facts(i);
        OnlyThisButton.Content = i.Service is not null && !i.Service.Contains(',', StringComparison.Ordinal) ? "Only this service" : "Only this program";
        OnlyThisButton.IsEnabled = i.App is not null;
        OpenFolderButton.IsEnabled = i.App is not null && File.Exists(i.App);

        if (i.Remote is { } address && !_hostNames.ContainsKey(address) && NetworkFacts.AddressScope(address) != "unknown")
        {
            LookUpHost(address);
        }
    }

    private List<Fact> Facts(TrafficItem i)
    {
        var c = CultureInfo.CurrentCulture;
        var facts = new List<Fact>();
        var inbound = i.Direction == "in";
        var times = i.Count == 1 ? "once" : $"{Fmt.Count(i.Count)} times";
        var span = i.FirstUtc == i.LastUtc
            ? i.LastUtc.ToLocalTime().ToString("g", c)
            : $"{i.FirstUtc.ToLocalTime().ToString("g", c)} – {i.LastUtc.ToLocalTime().ToString("g", c)}";
        facts.Add(new Fact("Connection", $"{(inbound ? "Inbound (another machine connected to this PC)" : "Outbound (this PC connected out)")}, {i.Protocol ?? "?"}, {times}: {span}"));

        if (i.Remote is { } remote)
        {
            var host = _hostNames.TryGetValue(remote, out var name) ? (name.Length == 0 ? "no host name found" : name) : "looking up the host name…";
            facts.Add(new Fact(inbound ? "From" : "To", $"{remote} · {NetworkFacts.AddressScope(remote)} · {host}"));
        }

        if (i.Port > 0)
        {
            var known = NetworkFacts.PortName(i.Port) ?? "no well-known service";
            facts.Add(new Fact(inbound ? "Port on this PC" : "Port on the other side", $"{i.Port} ({known})"));
        }

        if (i.Local is { } local)
        {
            facts.Add(new Fact("Local address and port", inbound
                ? local
                : $"{local} (Windows picks this source port for each new connection)"));
        }

        facts.Add(new Fact(i.Allowed ? "Why it was allowed" : "Why it was blocked",
            i.WhyLabel + (i.FilterId != 0 ? $" · CrioFire filter {i.FilterId}" : string.Empty)));

        facts.Add(new Fact("Program", ProgramFacts(i.App)));
        if (i.Service is { } services)
        {
            var all = WindowsServiceList.Read().ToDictionary(s => s.Name, s => s.DisplayName, StringComparer.OrdinalIgnoreCase);
            facts.Add(new Fact("Windows service", string.Join(", ", services.Split(',', StringSplitOptions.TrimEntries)
                .Select(s => all.TryGetValue(s, out var display) ? $"{display} ({s})" : s))));
        }

        facts.Add(new Fact("Rules for it", RuleFacts(i)));
        facts.Add(new Fact("Right now", LiveFacts(i.App)));
        return facts;
    }

    private static string ProgramFacts(string? app)
    {
        if (string.IsNullOrEmpty(app))
        {
            return "Unknown: Windows did not report a program.";
        }

        if (KnownApps.IsKernel(app))
        {
            return "The Windows kernel: file and printer sharing, NetBIOS, ICMP and other system traffic.";
        }

        if (!File.Exists(app))
        {
            return $"{app} (not found on this PC any more)";
        }

        try
        {
            var v = FileVersionInfo.GetVersionInfo(app);
            var parts = new[] { v.FileDescription, v.CompanyName, string.IsNullOrWhiteSpace(v.FileVersion) ? null : $"version {v.FileVersion}" }
                .Where(p => !string.IsNullOrWhiteSpace(p))
                .ToList();
            return parts.Count == 0 ? "No description in the file." : string.Join(" · ", parts);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return "Could not read the file's details.";
        }
    }

    private string RuleFacts(TrafficItem i)
    {
        var lines = new List<string>();
        foreach (var r in _model.Rules)
        {
            var mine = (r.Kind == nameof(FilterKind.AppRule) || r.Kind == nameof(FilterKind.NetRule)) && i.App is not null
                && string.Equals(r.App, i.App, StringComparison.OrdinalIgnoreCase);
            var service = r.Kind == nameof(FilterKind.ServiceRule) && i.Service is not null && r.Service is not null
                && i.Service.Split(',', StringSplitOptions.TrimEntries).Contains(r.Service, StringComparer.OrdinalIgnoreCase);
            if (mine || service)
            {
                var text = r.Summary ?? $"{r.Action} {r.Direction}" + (service ? $" (service {r.Service})" : string.Empty);
                if (!lines.Contains(text))
                {
                    lines.Add(text);
                }
            }
        }

        return lines.Count == 0 ? "None. The mode decides (" + AppModel.ModeName(_model.Mode) + " mode)." : string.Join("\n", lines);
    }

    private static string LiveFacts(string? app)
    {
        if (string.IsNullOrEmpty(app))
        {
            return "–";
        }

        var live = ConnectionTable.Read()
            .Where(c => KnownApps.IsKernel(app) ? c.ProcessId == 4 : string.Equals(c.ProcessPath, app, StringComparison.OrdinalIgnoreCase))
            .ToList();
        if (live.Count == 0)
        {
            return "No open connections or listening ports.";
        }

        var pids = string.Join(", ", live.Select(c => c.ProcessId).Distinct().Order());
        var listening = live.Count(c => c.Remote is null);
        return $"{live.Count - listening} open connections, {listening} listening ports · process {pids}";
    }

    private async void LookUpHost(string address)
    {
        _hostNames[address] = string.Empty;   // one lookup per address
        string name;
        try
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(4));
            var entry = await Dns.GetHostEntryAsync(address, timeout.Token);
            name = entry.HostName == address ? string.Empty : entry.HostName;
        }
        catch (Exception ex) when (ex is SocketException or OperationCanceledException or ArgumentException)
        {
            name = string.Empty;
        }

        _hostNames[address] = name;
        if (_shown?.Item.Remote == address)
        {
            DetailFacts.ItemsSource = Facts(_shown.Item);
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

    private void OnOpenFolder(object sender, RoutedEventArgs e)
    {
        if (_shown?.Item.App is { } app && File.Exists(app))
        {
            Process.Start(new ProcessStartInfo("explorer.exe", $"/select,\"{app}\"") { UseShellExecute = true });
        }
    }

    private void OnCopy(object sender, RoutedEventArgs e)
    {
        if (_shown is not { } row)
        {
            return;
        }

        var text = string.Join(Environment.NewLine,
            new[] { row.Program, row.Detail, row.Why }.Concat(Facts(row.Item).Select(f => $"{f.Label}: {f.Value}")));
        try
        {
            Clipboard.SetText(text);
            _model.Say("Copied the details.");
        }
        catch (System.Runtime.InteropServices.ExternalException)
        {
            _model.Say("The clipboard is busy; try again.");
        }
    }
}
