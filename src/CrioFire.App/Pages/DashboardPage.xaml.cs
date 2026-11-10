using System.Windows;
using System.Windows.Controls;
using CrioFire.Core;
using CrioFire.Core.Api;

namespace CrioFire.App.Pages;

/// <summary>The home screen: protection status and mode, today at a glance, decisions waiting, live connections.</summary>
public partial class DashboardPage : UserControl, IPage
{
    private const double ChartHeight = 190;
    private readonly AppModel _model;

    internal DashboardPage(AppModel model)
    {
        _model = model;
        InitializeComponent();
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

    public void Refresh()
    {
        UpdateProtection();
        UpdatePending();

        var rules = _model.AppRules.ToList();
        var allowApps = rules.Where(r => r.Action == "allow").Select(r => r.App).Distinct(StringComparer.OrdinalIgnoreCase).Count();
        var blockApps = rules.Where(r => r.Action == "block").Select(r => r.App).Distinct(StringComparer.OrdinalIgnoreCase).Count();
        var temporary = rules.Where(r => r.ExpiresUtc is not null).Select(r => r.App).Distinct(StringComparer.OrdinalIgnoreCase).Count();
        AllowChip.Text = allowApps == 1 ? "1 program allowed" : $"{allowApps} programs allowed";
        BlockChip.Text = blockApps == 1 ? "1 block rule" : $"{blockApps} block rules";
        KpiAllowed.Text = Fmt.Count(allowApps);
        KpiAllowedNote.Text = temporary == 0 ? "no temporary rules" : $"{temporary} temporary";

        var live = ConnectionTable.Read().Where(c => c.Remote is not null).ToList();
        KpiLive.Text = Fmt.Count(live.Count);
        KpiLiveNote.Text = $"from {live.Select(c => c.ProcessId).Distinct().Count()} programs";
        LiveList.ItemsSource = live
            .Where(c => c.State == "Established")
            .OrderBy(c => c.ProcessPath, StringComparer.OrdinalIgnoreCase)
            .Take(6)
            .Select(LiveRow.From)
            .ToList();

        var report = _model.Status is null ? null : Service.Call(new ApiRequest { Op = ApiOps.Report, Period = ReportBuilder.Day }, out _)?.Report;
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
