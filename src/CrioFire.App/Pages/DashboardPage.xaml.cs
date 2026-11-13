using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Media3D;
using CrioFire.Core;
using CrioFire.Core.Api;

namespace CrioFire.App.Pages;

/// <summary>The home screen: protection status and mode, today at a glance, decisions waiting, live connections.</summary>
public partial class DashboardPage : UserControl, IPage
{
    private const double ChartHeight = 190;
    private readonly AppModel _model;
    private DashboardData? _loaded;

    internal DashboardPage(AppModel model)
    {
        _model = model;
        InitializeComponent();
        foreach (var list in new FrameworkElement[] { TopApps, AllowedList, PendingList, LiveList })
        {
            RowMenu.Attach(list, model, RowMenu.From);
        }

        PendingList.ItemsSource = model.Pending;
        model.Pending.CollectionChanged += (_, _) => UpdatePending();
    }

    public string Title => DateTime.Now.Hour switch
    {
        < 12 => "Good morning",
        < 18 => "Good afternoon",
        _ => "Good evening",
    };

    public string Subtitle => "Here is what CrioFire did on this PC in the last 24 hours.";

    public FrameworkElement? Actions => null;

    public TimeSpan? AutoRefresh => TimeSpan.FromSeconds(10);

    /// <summary>The slow part of a refresh: the connection table and today's report.</summary>
    private sealed record DashboardData(IReadOnlyList<LiveConnection> Live, ReportInfo? Report);

    public async Task LoadAsync()
    {
        var withReport = _model.Status is not null;
        _loaded = await Task.Run(() => Read(withReport));
    }

    private static DashboardData Read(bool withReport) => new(
        ConnectionTable.Read(),
        withReport ? Service.Call(new ApiRequest { Op = ApiOps.Report, Period = ReportBuilder.Day }, out _)?.Report : null);

    public void Refresh()
    {
        var data = _loaded ?? Read(_model.Status is not null);
        _loaded = null;
        UpdateProtection();
        UpdatePending();

        var rules = _model.AppRules.ToList();
        var allowApps = rules.Where(r => r.Action == "allow").Select(r => r.App).Distinct(StringComparer.OrdinalIgnoreCase).Count();
        var blockApps = rules.Where(r => r.Action == "block").Select(r => r.App).Distinct(StringComparer.OrdinalIgnoreCase).Count();
        var temporary = rules.Where(r => r.ExpiresUtc is not null).Select(r => r.App).Distinct(StringComparer.OrdinalIgnoreCase).Count();
        AllowChip.Text = (allowApps == 1 ? "1 program allowed" : $"{allowApps} programs allowed") + (temporary == 0 ? string.Empty : $" ({temporary} temporary)");
        BlockChip.Text = blockApps == 1 ? "1 block rule" : $"{blockApps} block rules";
        AutoChip.Text = AutoChipText();

        var live = data.Live.Where(c => c.Remote is not null).ToList();
        KpiLive.Text = Fmt.Count(live.Count);
        KpiLiveNote.Text = $"from {live.Select(c => c.ProcessId).Distinct().Count()} programs";
        LiveList.ItemsSource = live
            .Where(c => c.State == "Established")
            .OrderBy(c => c.ProcessPath, StringComparer.OrdinalIgnoreCase)
            .Take(6)
            .Select(c => LiveRow.From(c))
            .ToList();

        var report = data.Report;
        UpdateAllowed(report);
        if (report is null)
        {
            KpiBlocked.Text = "–";
            KpiBlockedNote.Text = "Reports need the CrioFire service.";
            HourBars.ItemsSource = null;
            TopApps.ItemsSource = null;
            ChartEmpty.Visibility = Visibility.Visible;
            TopAppsEmpty.Visibility = Visibility.Visible;
            return;
        }

        KpiBlocked.Text = Fmt.Count(report.Total);
        KpiBlockedNote.Text = $"{Fmt.Count(report.ByRule)} by your rules · {Fmt.Count(report.ByMode)} with no rule";
        HourBars.ItemsSource = Bars.From(report.Buckets, ChartHeight, _ => string.Empty, b => $"{Fmt.Time(b.StartUtc)}–{Fmt.Time(b.StartUtc.AddHours(1))}");
        ChartEmpty.Visibility = report.Total == 0 ? Visibility.Visible : Visibility.Collapsed;
        if (report.Buckets.Count > 12)
        {
            AxisStart.Text = Fmt.Time(report.Buckets[0].StartUtc);
            AxisMid.Text = Fmt.Time(report.Buckets[12].StartUtc);
        }

        var top = report.TopPrograms.Take(5).ToList();
        var max = Math.Max(1, top.Count == 0 ? 1 : top.Max(p => p.Count));
        TopApps.ItemsSource = top.Select(p => new ShareRow(Bars.Name(p.App), p.App, Fmt.Count(p.Count), (double)p.Count / max)).ToList();
        TopAppsEmpty.Visibility = top.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
    }

    private string AutoChipText()
    {
        if (_model.Mode == "learning")
        {
            return "Learning: programs without a rule may connect";
        }

        var on = _model.AutoRules.Where(r => r.Enabled).Select(r => r.Name switch
        {
            AutoRulePolicy.WindowsKernel => "the Windows kernel",
            AutoRulePolicy.LocalNetwork => "the local network",
            _ => "Windows services",
        }).ToList();
        return on.Count == 0 ? "Only loopback is allowed automatically" : $"Loopback and {string.Join(" and ", on)} allowed automatically";
    }

    private void UpdateAllowed(ReportInfo? report)
    {
        if (report is null)
        {
            KpiAllowed.Text = "–";
            KpiAllowedNote.Text = "needs the CrioFire service";
            AllowedList.ItemsSource = null;
            AllowedNote.Text = string.Empty;
            AllowedEmpty.Visibility = Visibility.Visible;
            return;
        }

        KpiAllowed.Text = Fmt.Count(report.AllowedTotal);
        KpiAllowedNote.Text = $"{Fmt.Count(report.AllowedAutomatic)} automatically · {Fmt.Count(report.AllowedProgramCount)} programs and services";
        AllowedNote.Text = $"{Fmt.Count(report.AllowedTotal)} connections allowed, {Fmt.Count(report.AllowedAutomatic)} of them by automatic rules or with no rule.";

        var chipIce = (System.Windows.Media.Brush)FindResource("ChipIceBrush");
        var chipIceText = (System.Windows.Media.Brush)FindResource("ChipIceTextBrush");
        var chipAuto = (System.Windows.Media.Brush)FindResource("InsetBrush");
        var chipAutoText = (System.Windows.Media.Brush)FindResource("Text2Brush");
        var top = (report.TopAllowedPrograms ?? []).Where(p => p.Reason != nameof(AllowReason.Loopback)).Take(6).ToList();
        var max = Math.Max(1, top.Count == 0 ? 1 : top.Max(p => p.Count));
        AllowedList.ItemsSource = top.Select(p =>
        {
            var (name, detail) = Who.Of(p.App, p.Service);
            var automatic = AllowReasons.IsAutomatic(p.Reason);
            return new AllowedRow(name, detail, p.App, p.Service, Fmt.Count(p.Count), (double)p.Count / max,
                AllowReasons.Label(p.Reason, p.Direction), p.Direction, Fmt.Ago(p.LastUtc),
                automatic ? chipAuto : chipIce, automatic ? chipAutoText : chipIceText);
        }).ToList();
        AllowedEmpty.Visibility = top.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
    }

    private void OnBlockAllowed(object sender, RoutedEventArgs e)
    {
        if (sender is Button { Tag: AllowedRow row } && Window.GetWindow(this) is { } owner)
        {
            _model.Decide(owner, row.App, row.Service, "block");
        }
    }

    private void OnOpenAllowed(object sender, RoutedEventArgs e) => _model.ShowAllowed();

    /// <summary>A click on a panel (not on a button or switch inside it) opens its full view.</summary>
    private void OnPanel(object sender, MouseButtonEventArgs e)
    {
        if (e.ChangedButton != MouseButton.Left || FromControl(e.OriginalSource as DependencyObject, sender as DependencyObject))
        {
            return;
        }

        e.Handled = true;
        switch ((sender as FrameworkElement)?.Tag as string)
        {
            case "blocked":
                _model.OpenActivity(new ActivityQuery("blocked"));
                break;
            case "blocked-most":
                _model.OpenActivity(new ActivityQuery("blocked", Sort: "count"));
                break;
            case "allowed":
                _model.OpenActivity(new ActivityQuery("allowed"));
                break;
            case "allowed-most":
                _model.OpenActivity(new ActivityQuery("allowed", Sort: "count"));
                break;
            case "waiting":
                _model.OpenActivity(new ActivityQuery("blocked", Why: "norule"));
                break;
            case "live":
                _model.GoTo("Connections");
                break;
            case "rules":
                _model.GoTo("Rules");
                break;
        }
    }

    /// <summary>A program row in "Blocked most" or "Waiting for your decision": its blocked connections.</summary>
    private void OnTopAppClick(object sender, MouseButtonEventArgs e)
    {
        if (e.ChangedButton != MouseButton.Left || FromControl(e.OriginalSource as DependencyObject, sender as DependencyObject))
        {
            return;
        }

        e.Handled = true;
        if ((sender as FrameworkElement)?.Tag is string app && app.Length > 0)
        {
            _model.OpenActivity(new ActivityQuery("blocked", App: app));
        }
    }

    /// <summary>A row in "Allowed most": that program's or service's allowed connections.</summary>
    private void OnAllowedRowClick(object sender, MouseButtonEventArgs e)
    {
        if (e.ChangedButton != MouseButton.Left || FromControl(e.OriginalSource as DependencyObject, sender as DependencyObject))
        {
            return;
        }

        e.Handled = true;
        if ((sender as FrameworkElement)?.Tag is AllowedRow row)
        {
            var services = (row.Service ?? string.Empty).Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            _model.OpenActivity(services.Length == 1
                ? new ActivityQuery("allowed", Service: services[0])
                : new ActivityQuery("allowed", App: row.App));
        }
    }

    /// <summary>True when the click landed on a button, switch or other control inside the panel.</summary>
    private static bool FromControl(DependencyObject? source, DependencyObject? panel)
    {
        for (var d = source; d is not null && d != panel; d = d is Visual or Visual3D ? VisualTreeHelper.GetParent(d) : LogicalTreeHelper.GetParent(d))
        {
            if (d is ButtonBase or TextBox)
            {
                return true;
            }
        }

        return false;
    }

    private void UpdateProtection()
    {
        var status = _model.Status;
        var mode = _model.Mode;
        ModeLearning.IsChecked = mode == "learning";
        ModeAsk.IsChecked = mode == "ask";
        ModeAllowList.IsChecked = mode == "allowlist";

        if (status is null || !status.Installed)
        {
            Ring.Data = Arcs.Arc(0.02, 84, 72);
            ProtectedText.Text = status is null ? "Offline" : "Not set up";
            ModeText.Text = string.Empty;
            ShieldIcon.SetResourceReference(System.Windows.Shapes.Shape.StrokeProperty, "FireTextBrush");
            Headline.Text = status is null ? "The CrioFire service is not running" : "CrioFire is not registered yet";
            Body.Text = status is null
                ? (_model.Error ?? "Start it with 'sc start criofire' from an administrator prompt.")
                : "Run 'criofire install' from an administrator prompt to register CrioFire with the Windows Filtering Platform.";
            return;
        }

        if (_model.PanicMode != "off")
        {
            var block = _model.PanicMode == "block";
            ShieldIcon.SetResourceReference(System.Windows.Shapes.Shape.StrokeProperty, "FireTextBrush");
            Ring.Data = Arcs.Arc(block ? 1 : 0.02, 84, 72);
            ProtectedText.Text = "Panic";
            ModeText.Text = block ? "Everything blocked" : "Rules paused";
            Headline.Text = block ? "All network traffic is blocked" : "Everything is allowed for now";
            Body.Text = (block
                    ? "No new connection gets in or out, whatever your rules say. Programs on this PC can still talk to each other."
                    : "Every program may connect. Your rules and the mode are paused, not deleted.")
                + $" {AppModel.ModeName(mode)} mode and all your rules come back with 'Resume my rules' at the top.";
            return;
        }

        ShieldIcon.SetResourceReference(System.Windows.Shapes.Shape.StrokeProperty, "IceTextBrush");
        ProtectedText.Text = "Protected";
        ModeText.Text = $"{AppModel.ModeName(mode)} mode";
        (Ring.Data, Headline.Text, Body.Text) = mode switch
        {
            "ask" => (Arcs.Arc(0.78, 84, 72), "New programs need your OK",
                "A program without a rule is stopped the moment it tries to connect out, and CrioFire asks you: allow it, allow it for an hour, or keep it blocked."),
            "allowlist" => (Arcs.Arc(1, 84, 72), "Only programs you trust",
                "Programs without an allow rule are blocked silently. Nothing new reaches the network until you add it to your rules."),
            _ => (Arcs.Arc(0.45, 84, 72), "Watching, not blocking",
                "Programs without a rule may connect. CrioFire only blocks what your rules say, so you can see what talks to the network before you lock it down."),
        };
    }

    private void UpdatePending()
    {
        var count = _model.Pending.Count;
        KpiWaiting.Text = Fmt.Count(count);
        KpiWaitingNote.Text = _model.Mode == "ask" ? "new programs in Ask mode" : "alerts come in Ask mode";
        PendingEmpty.Visibility = count == 0 ? Visibility.Visible : Visibility.Collapsed;
        PendingEmpty.Text = _model.Mode == "ask"
            ? "Nothing waiting. Programs without a rule show up here when they try to connect."
            : "Nothing waiting. Switch to Ask mode to decide about each new program.";
    }

    private void OnMode(object sender, RoutedEventArgs e)
    {
        if (sender is RadioButton { Tag: string mode } && Window.GetWindow(this) is { } owner)
        {
            _model.SetMode(owner, mode);
            UpdateProtection();
        }
    }

    private void OnAllowPending(object sender, RoutedEventArgs e)
    {
        if (sender is Button { Tag: string app })
        {
            _model.SetRule(app, "allow");
        }
    }

    private void OnBlockPending(object sender, RoutedEventArgs e)
    {
        if (sender is Button { Tag: string app })
        {
            _model.SetRule(app, "block");
        }
    }

    private void OnOpenReports(object sender, RoutedEventArgs e) => _model.GoTo("Reports");

    private void OnOpenConnections(object sender, RoutedEventArgs e) => _model.GoTo("Connections");
}
