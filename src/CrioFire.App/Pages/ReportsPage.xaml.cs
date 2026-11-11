using System.Globalization;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using CrioFire.Core;
using CrioFire.Core.Api;
using Microsoft.Win32;

namespace CrioFire.App.Pages;

/// <summary>What CrioFire blocked over 24 hours, 7 days or 30 days, from the service's traffic log.</summary>
public partial class ReportsPage : UserControl, IPage
{
    private const double ChartHeight = 200;
    private readonly AppModel _model;
    private string _period = ReportBuilder.Week;
    private ReportInfo? _report;

    internal ReportsPage(AppModel model)
    {
        _model = model;
        InitializeComponent();
        foreach (var list in new FrameworkElement[] { ProgramList, DestinationList, AllowedList, AllowedDestinationList })
        {
            RowMenu.Attach(list, model, RowMenu.From);
        }
    }

    public string Title => "Reports";

    public string Subtitle { get; private set; } = string.Empty;

    public FrameworkElement? Actions => null;

    public TimeSpan? AutoRefresh => null;

    public void Refresh()
    {
        _report = Service.Call(new ApiRequest { Op = ApiOps.Report, Period = _period }, out var error)?.Report;
        if (_report is not { } r)
        {
            Subtitle = error ?? "No report available.";
            ClearAll();
            return;
        }

        var c = CultureInfo.CurrentCulture;
        var lastDay = r.ToUtc.ToLocalTime().AddMinutes(-1);
        Subtitle = _period == ReportBuilder.Day
            ? $"The 24 hours up to {lastDay.AddMinutes(1).ToString("HH:mm", c)} today"
            : $"{r.FromUtc.ToLocalTime().ToString("MMMM d", c)} – {lastDay.ToString("MMMM d", c)}";

        SumBlocked.Text = Fmt.Count(r.Total);
        if (r.PreviousTotal == 0)
        {
            SumBlockedNote.Text = r.Total == 0 ? "nothing blocked" : "nothing in the period before";
            SumBlockedNote.SetResourceReference(TextBlock.ForegroundProperty, "Text2Brush");
        }
        else
        {
            var change = (r.Total - r.PreviousTotal) * 100.0 / r.PreviousTotal;
            SumBlockedNote.Text = $"{(change >= 0 ? "▲" : "▼")} {Math.Abs(change):0}% vs the period before";
            SumBlockedNote.SetResourceReference(TextBlock.ForegroundProperty, change >= 0 ? "FireTextBrush" : "IceTextBrush");
        }

        SumPrograms.Text = Fmt.Count(r.ProgramCount);
        var modePrograms = r.TopPrograms.Count(p => p.ByRule < p.Count);
        SumProgramsNote.Text = modePrograms == 0 ? "all stopped by your rules" : $"{modePrograms} of the top ones had no rule";
        SumDestinations.Text = Fmt.Count(r.DestinationCount);
        SumMode.Text = Fmt.Count(r.ByMode);

        ChartTitle.Text = _period == ReportBuilder.Day ? "Blocked connections per hour" : "Blocked connections per day";
        var bars = Bars.From(r.Buckets, ChartHeight, b => BucketLabel(b, r.Buckets.Count), b => BucketTip(b));
        DayBars.ItemsSource = bars;
        DayLabels.ItemsSource = bars;
        var max = r.Buckets.Count == 0 ? 0 : r.Buckets.Max(b => b.Total);
        AxisTop.Text = max == 0 ? string.Empty : Fmt.Count(max);
        AxisMid.Text = max < 2 ? string.Empty : Fmt.Count(max / 2);
        ChartEmpty.Visibility = r.Total == 0 ? Visibility.Visible : Visibility.Collapsed;

        var fire = (Brush)FindResource("FireGradientBrush");
        var ice = (Brush)FindResource("IceBrush");
        var chipFire = (Brush)FindResource("ChipFireBrush");
        var chipFireText = (Brush)FindResource("ChipFireTextBrush");
        var chipIce = (Brush)FindResource("ChipIceBrush");
        var chipIceText = (Brush)FindResource("ChipIceTextBrush");
        var top = Math.Max(1, r.TopPrograms.Count == 0 ? 1 : r.TopPrograms.Max(p => p.Count));
        ProgramList.ItemsSource = r.TopPrograms.Select(p =>
        {
            var byRule = p.ByRule * 2 >= p.Count;
            return new ProgramRow(
                Bars.Name(p.App), p.App, Fmt.Count(p.Count), (double)p.Count / top,
                byRule ? "Your rule" : "No rule yet", Fmt.Ago(p.LastUtc),
                byRule ? fire : ice, byRule ? chipFire : chipIce, byRule ? chipFireText : chipIceText);
        }).ToList();
        ProgramsEmpty.Visibility = r.TopPrograms.Count == 0 ? Visibility.Visible : Visibility.Collapsed;

        var directed = r.Outbound + r.Inbound;
        var outShare = directed == 0 ? 0 : (double)r.Outbound / directed;
        DonutArc.Data = directed == 0 ? null : Arcs.Arc(outShare, 66, 52);
        OutShare.Text = directed == 0 ? "–" : $"{outShare * 100:0}%";
        OutCount.Text = $"Outbound · {Fmt.Count(r.Outbound)}";
        InCount.Text = $"Inbound · {Fmt.Count(r.Inbound)}";

        DestinationList.ItemsSource = r.TopDestinations.Take(6)
            .Select(d => new DestinationRow(d.Address, d.Port.ToString(c), Fmt.Count(d.Count))).ToList();
        DestinationsEmpty.Visibility = r.TopDestinations.Count == 0 ? Visibility.Visible : Visibility.Collapsed;

        ShowAllowed(r, chipIce, chipIceText);
    }

    private void ShowAllowed(ReportInfo r, Brush chipIce, Brush chipIceText)
    {
        var c = CultureInfo.CurrentCulture;
        var chipAuto = (Brush)FindResource("InsetBrush");
        var chipAutoText = (Brush)FindResource("Text2Brush");
        var change = r.AllowedPrevious == 0 ? string.Empty
            : $" ({((r.AllowedTotal - r.AllowedPrevious) >= 0 ? "▲" : "▼")} {Math.Abs((r.AllowedTotal - r.AllowedPrevious) * 100.0 / r.AllowedPrevious):0}% vs the period before)";
        AllowedHeadline.Text = $"{Fmt.Count(r.AllowedTotal)} connections from {Fmt.Count(r.AllowedProgramCount)} programs and services{change}; "
            + $"{Fmt.Count(r.AllowedAutomatic)} were allowed by automatic rules or with no rule at all.";

        var programs = r.TopAllowedPrograms ?? [];
        var top = Math.Max(1, programs.Count == 0 ? 1 : programs.Max(p => p.Count));
        AllowedList.ItemsSource = programs.Select(p =>
        {
            var (name, detail) = Who.Of(p.App, p.Service);
            var automatic = AllowReasons.IsAutomatic(p.Reason);
            return new AllowedRow(name, detail, p.App, p.Service, Fmt.Count(p.Count), (double)p.Count / top,
                AllowReasons.Label(p.Reason, p.Direction), Who.Direction(p.Direction), Fmt.Ago(p.LastUtc),
                automatic ? chipAuto : chipIce, automatic ? chipAutoText : chipIceText);
        }).ToList();
        AllowedEmpty.Visibility = programs.Count == 0 ? Visibility.Visible : Visibility.Collapsed;

        var reasons = r.AllowedReasons ?? [];
        var most = Math.Max(1, reasons.Count == 0 ? 1 : reasons.Max(x => x.Count));
        ReasonList.ItemsSource = reasons
            .Select(x => new ShareRow(AllowReasons.Label(x.Reason, null), x.Reason, Fmt.Count(x.Count), (double)x.Count / most))
            .ToList();
        ReasonsEmpty.Visibility = reasons.Count == 0 ? Visibility.Visible : Visibility.Collapsed;

        var destinations = r.TopAllowedDestinations ?? [];
        AllowedDestinationList.ItemsSource = destinations.Take(6)
            .Select(d => new DestinationRow(d.Address, d.Port.ToString(c), Fmt.Count(d.Count))).ToList();
        AllowedDestinationsEmpty.Visibility = destinations.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
    }

    private string BucketLabel(ReportBucket b, int count)
    {
        var local = b.StartUtc.ToLocalTime();
        var c = CultureInfo.CurrentCulture;
        return _period switch
        {
            ReportBuilder.Day => local.Hour % 3 == 0 ? local.ToString("HH", c) : string.Empty,
            ReportBuilder.Month => local.Day % 5 == 0 || count <= 10 ? local.ToString("d MMM", c) : string.Empty,
            _ => local.ToString("ddd", c),
        };
    }

    private string BucketTip(ReportBucket b)
    {
        var local = b.StartUtc.ToLocalTime();
        var c = CultureInfo.CurrentCulture;
        return _period == ReportBuilder.Day
            ? $"{local.ToString("HH:mm", c)}–{local.AddHours(1).ToString("HH:mm", c)}"
            : local.ToString("dddd, MMMM d", c);
    }

    private void ClearAll()
    {
        foreach (var t in new[] { SumBlocked, SumPrograms, SumDestinations, SumMode })
        {
            t.Text = "–";
        }

        SumBlockedNote.Text = SumProgramsNote.Text = string.Empty;
        DayBars.ItemsSource = DayLabels.ItemsSource = ProgramList.ItemsSource = DestinationList.ItemsSource = null;
        AllowedList.ItemsSource = ReasonList.ItemsSource = AllowedDestinationList.ItemsSource = null;
        AllowedHeadline.Text = string.Empty;
        AllowedEmpty.Visibility = ReasonsEmpty.Visibility = AllowedDestinationsEmpty.Visibility = Visibility.Visible;
        DonutArc.Data = null;
        OutShare.Text = "–";
        ChartEmpty.Visibility = ProgramsEmpty.Visibility = DestinationsEmpty.Visibility = Visibility.Visible;
    }

    private void OnPeriod(object sender, RoutedEventArgs e)
    {
        if (sender is RadioButton { Tag: string period })
        {
            _period = period;
            _model.NotifyChanged();   // the window refreshes this page and re-reads the subtitle
        }
    }

    private void OnExportCsv(object sender, RoutedEventArgs e)
    {
        if (_report is null)
        {
            _model.Say("There is no report to export yet.");
            return;
        }

        var dialog = new SaveFileDialog
        {
            Title = "Export report",
            Filter = "CSV file (*.csv)|*.csv",
            FileName = $"criofire-report-{_period}-{DateTime.Now:yyyy-MM-dd}.csv",
        };
        if (dialog.ShowDialog(Window.GetWindow(this)) == true)
        {
            try
            {
                File.WriteAllText(dialog.FileName, ReportBuilder.ToCsv(_report));
                _model.Say($"Saved {Path.GetFileName(dialog.FileName)}.");
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                _model.Say($"Could not save the file: {ex.Message}");
            }
        }
    }

    /// <summary>Prints the report; choose "Microsoft Print to PDF" to get a PDF file.</summary>
    private void OnSavePdf(object sender, RoutedEventArgs e)
    {
        var dialog = new PrintDialog();
        if (dialog.ShowDialog() != true)
        {
            return;
        }

        var scale = Math.Min(dialog.PrintableAreaWidth / ReportRoot.ActualWidth, dialog.PrintableAreaHeight / ReportRoot.ActualHeight);
        var previous = ReportRoot.LayoutTransform;
        try
        {
            ReportRoot.LayoutTransform = new ScaleTransform(Math.Min(scale, 1), Math.Min(scale, 1));
            ReportRoot.UpdateLayout();
            dialog.PrintVisual(ReportRoot, $"CrioFire report – {Subtitle}");
            _model.Say("Report sent to the printer. Choose \"Microsoft Print to PDF\" to save it as a PDF.");
        }
        finally
        {
            ReportRoot.LayoutTransform = previous;
            ReportRoot.UpdateLayout();
        }
    }
}
