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
    private (string Period, ReportInfo? Report, string? Error)? _loaded;
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

    public string Title => L.T("Reports");

    public string Subtitle { get; private set; } = string.Empty;

    public FrameworkElement? Actions => null;

    public TimeSpan? AutoRefresh => null;

    public async Task LoadAsync()
    {
        var period = _period;
        _loaded = await Task.Run(() => Read(period));
    }

    private static (string Period, ReportInfo? Report, string? Error) Read(string period)
    {
        var report = Service.Call(new ApiRequest { Op = ApiOps.Report, Period = period }, out var error)?.Report;
        return (period, report, error);
    }

    public void Refresh()
    {
        var data = _loaded is { } loaded && loaded.Period == _period ? loaded : Read(_period);
        _loaded = null;
        _report = data.Report;
        var error = data.Error;
        if (_report is not { } r)
        {
            Subtitle = error ?? L.T("No report available.");
            ClearAll();
            return;
        }

        var c = CultureInfo.CurrentCulture;
        var lastDay = r.ToUtc.ToLocalTime().AddMinutes(-1);
        Subtitle = _period == ReportBuilder.Day
            ? L.T($"The 24 hours up to {lastDay.AddMinutes(1).ToString("HH:mm", c)} today")
            : $"{r.FromUtc.ToLocalTime().ToString("MMMM d", c)} – {lastDay.ToString("MMMM d", c)}";

        SumBlocked.Text = Fmt.Count(r.Total);
        if (r.PreviousTotal == 0)
        {
            SumBlockedNote.Text = r.Total == 0 ? L.T("nothing blocked") : L.T("nothing in the period before");
            SumBlockedNote.SetResourceReference(TextBlock.ForegroundProperty, "Text2Brush");
        }
        else
        {
            var change = (r.Total - r.PreviousTotal) * 100.0 / r.PreviousTotal;
            SumBlockedNote.Text = L.T($"{(change >= 0 ? "▲" : "▼")} {Math.Abs(change):0}% vs the period before");
            SumBlockedNote.SetResourceReference(TextBlock.ForegroundProperty, change >= 0 ? "FireTextBrush" : "IceTextBrush");
        }

        SumPrograms.Text = Fmt.Count(r.ProgramCount);
        var modePrograms = r.TopPrograms.Count(p => p.ByRule < p.Count);
        SumProgramsNote.Text = modePrograms == 0 ? L.T("all stopped by your rules") : L.T($"{modePrograms} of the top ones had no rule");
        SumDestinations.Text = Fmt.Count(r.DestinationCount);
        SumMode.Text = Fmt.Count(r.ByMode);

        ChartTitle.Text = _period == ReportBuilder.Day ? L.T("Blocked connections per hour") : L.T("Blocked connections per day");
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
                byRule ? L.T("Your rule") : L.T("No rule yet"), Fmt.Ago(p.LastUtc),
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
            : L.T($" ({((r.AllowedTotal - r.AllowedPrevious) >= 0 ? "▲" : "▼")} {Math.Abs((r.AllowedTotal - r.AllowedPrevious) * 100.0 / r.AllowedPrevious):0}% vs the period before)");
        AllowedHeadline.Text = L.T($"{Fmt.Count(r.AllowedTotal)} connections from {Fmt.Count(r.AllowedProgramCount)} programs and services{change}; ")
            + L.T($"{Fmt.Count(r.AllowedAutomatic)} were allowed by automatic rules or with no rule at all.");

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
            _model.Say(L.T("There is no report to export yet."));
            return;
        }

        var dialog = new SaveFileDialog
        {
            Title = L.T("Export report"),
            Filter = L.T("CSV file (*.csv)|*.csv"),
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
                _model.Say(L.T($"Could not save the file: {ex.Message}"));
            }
        }
    }

    /// <summary>
    /// Saves the report as a PDF made for reading and printing: CrioFire Private Firewall and
    /// CrioSoft LLC on every page, page numbers, and tables over as many pages as they need.
    /// </summary>
    private void OnSavePdf(object sender, RoutedEventArgs e)
    {
        if (_report is null)
        {
            _model.Say(L.T("There is no report to save yet."));
            return;
        }

        var dialog = new SaveFileDialog
        {
            Title = L.T("Save report as PDF"),
            Filter = L.T("PDF document (*.pdf)|*.pdf"),
            FileName = $"criofire-report-{_period}-{DateTime.Now:yyyy-MM-dd}.pdf",
        };
        if (dialog.ShowDialog(Window.GetWindow(this)) != true)
        {
            return;
        }

        try
        {
            var input = new Reporting.ReportPdfInput(
                _report, TimeZoneInfo.Local, Environment.MachineName, _model.Mode, AppVersion(),
                _model.Rules, _model.AutoRules, LogoPng());
            File.WriteAllBytes(dialog.FileName, Reporting.ReportPdf.Build(input));
            _model.Say($"Saved {Path.GetFileName(dialog.FileName)}.");
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(dialog.FileName) { UseShellExecute = true });
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.ComponentModel.Win32Exception)
        {
            _model.Say(L.T($"Could not save the PDF: {ex.Message}"));
        }
        catch (Exception ex) when (ex is InvalidOperationException or ArgumentException or NotSupportedException)
        {
            _model.Say(L.T($"Could not create the PDF: {ex.Message}"));
        }
    }

    private static string AppVersion()
    {
        var version = typeof(ReportsPage).Assembly
            .GetCustomAttributes(typeof(System.Reflection.AssemblyInformationalVersionAttribute), false)
            .OfType<System.Reflection.AssemblyInformationalVersionAttribute>()
            .FirstOrDefault()?.InformationalVersion ?? "dev";
        var plus = version.IndexOf('+', StringComparison.Ordinal);
        return plus > 0 ? version[..plus] : version;
    }

    /// <summary>The CrioFire icon as PNG for the PDF's title, or null if it cannot be read.</summary>
    private static byte[]? LogoPng()
    {
        try
        {
            var info = Application.GetResourceStream(new Uri("pack://application:,,,/Assets/criofire.ico"));
            if (info is null)
            {
                return null;
            }

            using var stream = info.Stream;
            var decoder = new System.Windows.Media.Imaging.IconBitmapDecoder(stream,
                System.Windows.Media.Imaging.BitmapCreateOptions.None, System.Windows.Media.Imaging.BitmapCacheOption.OnLoad);
            var frame = decoder.Frames.OrderByDescending(f => f.PixelWidth).First();
            var encoder = new System.Windows.Media.Imaging.PngBitmapEncoder();
            encoder.Frames.Add(System.Windows.Media.Imaging.BitmapFrame.Create(frame));
            using var png = new MemoryStream();
            encoder.Save(png);
            return png.ToArray();
        }
        catch (Exception ex) when (ex is IOException or NotSupportedException or InvalidOperationException or FileFormatException)
        {
            return null;
        }
    }
}
