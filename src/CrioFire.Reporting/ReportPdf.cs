using System.Globalization;
using System.IO;
using CrioFire.Core;
using CrioFire.Core.Api;
using MigraDoc.DocumentObjectModel;
using MigraDoc.DocumentObjectModel.Tables;
using MigraDoc.Rendering;
using MdColor = MigraDoc.DocumentObjectModel.Color;

namespace CrioFire.Reporting;

/// <summary>What goes into a PDF report.</summary>
/// <param name="Mode">learning, ask or allowlist.</param>
/// <param name="LogoPng">The CrioFire icon as PNG, for the title; optional.</param>
public sealed record ReportPdfInput(
    ReportInfo Report,
    TimeZoneInfo Zone,
    string ComputerName,
    string Mode,
    string AppVersion,
    IReadOnlyList<RuleInfo> Rules,
    IReadOnlyList<AutoRuleInfo> AutoRules,
    byte[]? LogoPng = null,
    DateTime? GeneratedUtc = null);

/// <summary>
/// The report as a print-friendly PDF: Letter pages with CrioFire Private Firewall and CrioSoft LLC
/// in the header and footer, page numbers, dark text on white, and tables that continue across as
/// many pages as they need, with their column headings repeated on each page.
/// </summary>
public static class ReportPdf
{
    public const string Product = "CrioFire Private Firewall";
    public const string Company = "CrioSoft LLC";

    private const double PageWidthInches = 8.5;
    private const double PageHeightInches = 11;
    private const double SideMarginInches = 0.75;
    private const double ContentInches = PageWidthInches - (2 * SideMarginInches);   // 7 inches

    private static readonly MdColor Ink = new(0x0E, 0x1A, 0x2B);
    private static readonly MdColor Muted = new(0x5A, 0x6B, 0x82);
    private static readonly MdColor Fire = new(0xC8, 0x32, 0x1E);
    private static readonly MdColor Ice = new(0x13, 0x76, 0xA6);
    private static readonly MdColor HeadShade = new(0xE6, 0xF2, 0xF9);
    private static readonly MdColor Zebra = new(0xF6, 0xF9, 0xFC);
    private static readonly MdColor Line = new(0xD3, 0xDD, 0xE7);

    public static byte[] Build(ReportPdfInput input)
    {
        ArgumentNullException.ThrowIfNull(input);
        var document = Compose(input);
        var renderer = new PdfDocumentRenderer { Document = document };
        renderer.RenderDocument();
        renderer.PdfDocument.Info.Creator = $"{Product} {input.AppVersion}";
        using var stream = new MemoryStream();
        renderer.PdfDocument.Save(stream, false);
        return stream.ToArray();
    }

    /// <summary>The report as a MigraDoc document (before rendering).</summary>
    public static Document Compose(ReportPdfInput input)
    {
        ArgumentNullException.ThrowIfNull(input);
        var r = input.Report;
        var generated = input.GeneratedUtc ?? DateTime.UtcNow;
        var document = new Document();
        document.Info.Title = $"{Product} – traffic report, {PeriodName(r.Period)}";
        document.Info.Author = Company;
        document.Info.Subject = $"Blocked and allowed network connections on {input.ComputerName}";
        document.Info.Keywords = "CrioFire, firewall, report, CrioSoft";
        DefineStyles(document);

        var section = document.AddSection();
        var setup = section.PageSetup;
        setup.PageWidth = Unit.FromInch(PageWidthInches);
        setup.PageHeight = Unit.FromInch(PageHeightInches);
        setup.LeftMargin = setup.RightMargin = Unit.FromInch(SideMarginInches);
        setup.TopMargin = Unit.FromInch(0.95);
        setup.BottomMargin = Unit.FromInch(0.85);
        setup.HeaderDistance = Unit.FromInch(0.4);
        setup.FooterDistance = Unit.FromInch(0.4);

        Header(section);
        Footer(section, input, generated);
        Title(section, input, generated);

        Summary(section, r);
        OverTime(section, r, input.Zone);
        BlockedPrograms(section, r, input.Zone);
        Destinations(section, "Destinations blocked most", r.TopDestinations, "Blocked");
        AllowedReasons(section, r);
        AllowedPrograms(section, r, input.Zone);
        Destinations(section, "Destinations allowed most", r.TopAllowedDestinations ?? [], "Allowed");
        RulesSection(section, input);

        var end = section.AddParagraph();
        end.Style = "Note";
        end.Format.SpaceBefore = Unit.FromPoint(18);
        end.AddText($"{Product} by {Company}. Times are in {input.Zone.DisplayName}. ");
        end.AddText("Counts come from the CrioFire service's logs and cover the time it was running.");
        return document;
    }

    // ---- layout ----

    private static void DefineStyles(Document document)
    {
        var normal = document.Styles[StyleNames.Normal]!;
        normal.Font.Name = "Segoe UI";
        normal.Font.Size = Unit.FromPoint(9);
        normal.Font.Color = Ink;

        var heading = document.Styles.AddStyle("Section", StyleNames.Normal);
        heading.Font.Size = Unit.FromPoint(13);
        heading.Font.Bold = true;
        heading.ParagraphFormat.SpaceBefore = Unit.FromPoint(18);
        heading.ParagraphFormat.SpaceAfter = Unit.FromPoint(6);
        heading.ParagraphFormat.KeepWithNext = true;
        heading.ParagraphFormat.Borders.Bottom.Width = Unit.FromPoint(1);
        heading.ParagraphFormat.Borders.Bottom.Color = Ice;
        heading.ParagraphFormat.Borders.DistanceFromBottom = Unit.FromPoint(3);

        var sub = document.Styles.AddStyle("Subsection", StyleNames.Normal);
        sub.Font.Size = Unit.FromPoint(10.5);
        sub.Font.Bold = true;
        sub.ParagraphFormat.SpaceBefore = Unit.FromPoint(10);
        sub.ParagraphFormat.SpaceAfter = Unit.FromPoint(4);
        sub.ParagraphFormat.KeepWithNext = true;

        var note = document.Styles.AddStyle("Note", StyleNames.Normal);
        note.Font.Size = Unit.FromPoint(8);
        note.Font.Color = Muted;

        var cell = document.Styles.AddStyle("Cell", StyleNames.Normal);
        cell.Font.Size = Unit.FromPoint(8.5);
    }

    private static void Header(Section section)
    {
        var p = section.Headers.Primary.AddParagraph();
        p.Format.TabStops.AddTabStop(Unit.FromInch(ContentInches), TabAlignment.Right);
        p.Format.Borders.Bottom.Width = Unit.FromPoint(0.5);
        p.Format.Borders.Bottom.Color = Line;
        p.Format.Borders.DistanceFromBottom = Unit.FromPoint(4);
        p.Format.Font.Size = Unit.FromPoint(8.5);
        var name = p.AddFormattedText(Product, TextFormat.Bold);
        name.Color = Ice;
        p.AddTab();
        var right = p.AddFormattedText("Traffic report");
        right.Color = Muted;
    }

    private static void Footer(Section section, ReportPdfInput input, DateTime generatedUtc)
    {
        var p = section.Footers.Primary.AddParagraph();
        p.Format.TabStops.AddTabStop(Unit.FromInch(ContentInches), TabAlignment.Right);
        p.Format.Borders.Top.Width = Unit.FromPoint(0.5);
        p.Format.Borders.Top.Color = Line;
        p.Format.Borders.DistanceFromTop = Unit.FromPoint(4);
        p.Format.Font.Size = Unit.FromPoint(8);
        p.Format.Font.Color = Muted;
        p.AddText($"{Company} · {Product} {input.AppVersion} · {input.ComputerName} · {Local(generatedUtc, input.Zone, "g")}");
        p.AddTab();
        p.AddText("Page ");
        p.AddPageField();
        p.AddText(" of ");
        p.AddNumPagesField();
    }

    private static void Title(Section section, ReportPdfInput input, DateTime generatedUtc)
    {
        var r = input.Report;
        var brand = section.AddParagraph();
        if (input.LogoPng is { Length: > 0 } logo)
        {
            var image = brand.AddImage("base64:" + Convert.ToBase64String(logo));
            image.Height = Unit.FromPoint(30);
            image.LockAspectRatio = true;
            brand.AddText("  ");
        }

        var product = brand.AddFormattedText(Product, TextFormat.Bold);
        product.Size = Unit.FromPoint(16);
        product.Color = Ice;
        brand.AddLineBreak();
        var by = brand.AddFormattedText($"by {Company}");
        by.Size = Unit.FromPoint(9);
        by.Color = Muted;

        var title = section.AddParagraph();
        title.Format.SpaceBefore = Unit.FromPoint(14);
        var t = title.AddFormattedText($"Traffic report – {PeriodName(r.Period)}", TextFormat.Bold);
        t.Size = Unit.FromPoint(22);

        var facts = section.AddParagraph();
        facts.Format.SpaceBefore = Unit.FromPoint(4);
        facts.Format.Font.Color = Muted;
        facts.AddText($"{Local(r.FromUtc, input.Zone, "f")} – {Local(r.ToUtc, input.Zone, "f")}");
        facts.AddLineBreak();
        facts.AddText($"Computer {input.ComputerName} · {ModeName(input.Mode)} mode · generated {Local(generatedUtc, input.Zone, "f")}");
    }

    private static void Summary(Section section, ReportInfo r)
    {
        Heading(section, "Summary");
        var table = NewTable(section, [("", 2.6, false), ("", 0.9, true), ("", 2.6, false), ("", 0.9, true)], header: false);
        var change = r.PreviousTotal == 0 ? "–" : $"{(r.Total >= r.PreviousTotal ? "+" : "–")}{Math.Abs((r.Total - r.PreviousTotal) * 100.0 / r.PreviousTotal):0}%";
        var allowedChange = r.AllowedPrevious == 0 ? "–" : $"{(r.AllowedTotal >= r.AllowedPrevious ? "+" : "–")}{Math.Abs((r.AllowedTotal - r.AllowedPrevious) * 100.0 / r.AllowedPrevious):0}%";
        (string, string, string, string)[] rows =
        [
            ("Connections blocked", N(r.Total), "Connections allowed", N(r.AllowedTotal)),
            ("  by your rules", N(r.ByRule), "  automatically or with no rule", N(r.AllowedAutomatic)),
            ("  because they had no rule yet", N(r.ByMode), "Programs and services allowed", N(r.AllowedProgramCount)),
            ("  outbound / inbound", $"{N(r.Outbound)} / {N(r.Inbound)}", "Destinations blocked", N(r.DestinationCount)),
            ("Programs blocked", N(r.ProgramCount), "Allowed, change from the period before", allowedChange),
            ("Blocked, change from the period before", change, string.Empty, string.Empty),
        ];
        var i = 0;
        foreach (var (a, b, c, d) in rows)
        {
            var row = AddRow(table, i++, a, b, c, d);
            row.Cells[1].Format.Font.Color = Fire;
            row.Cells[3].Format.Font.Color = Ice;
            row.Cells[1].Format.Font.Bold = row.Cells[3].Format.Font.Bold = true;
        }
    }

    private static void OverTime(Section section, ReportInfo r, TimeZoneInfo zone)
    {
        Heading(section, r.Period == ReportBuilder.Day ? "Hour by hour" : "Day by day");
        var format = r.Period == ReportBuilder.Day ? "ddd HH:mm" : "ddd, MMM d";
        var table = NewTable(section, [("Starting", 2.2, false), ("By your rules", 1.2, true), ("No rule yet", 1.2, true), ("Blocked", 1.2, true), ("Allowed", 1.2, true)]);
        var i = 0;
        foreach (var b in r.Buckets)
        {
            AddRow(table, i++, Local(b.StartUtc, zone, format), N(b.ByRule), N(b.ByMode), N(b.Total), N(b.Allowed));
        }
    }

    private static void BlockedPrograms(Section section, ReportInfo r, TimeZoneInfo zone)
    {
        Heading(section, "Programs blocked most");
        if (r.TopPrograms.Count == 0)
        {
            Empty(section);
            return;
        }

        var table = NewTable(section, [("#", 0.35, true), ("Program", 3.55, false), ("Blocked", 0.85, true), ("By your rules", 0.95, true), ("Last seen", 1.3, false)]);
        var i = 0;
        foreach (var p in r.TopPrograms)
        {
            var row = AddRow(table, i, (i + 1).ToString(CultureInfo.CurrentCulture), string.Empty, N(p.Count), N(p.ByRule), Local(p.LastUtc, zone, "g"));
            Program(row.Cells[1], p.App, null, 3.55);
            i++;
        }
    }

    private static void Destinations(Section section, string title, List<ReportDestination> destinations, string countHeader)
    {
        Heading(section, title);
        if (destinations.Count == 0)
        {
            Empty(section);
            return;
        }

        var table = NewTable(section, [("Address", 2.6, false), ("Port", 0.7, true), ("Usually", 2.6, false), (countHeader, 1.1, true)]);
        var i = 0;
        foreach (var d in destinations)
        {
            AddRow(table, i++, d.Address, d.Port > 0 ? d.Port.ToString(CultureInfo.InvariantCulture) : "–", NetworkFacts.PortName(d.Port) ?? string.Empty, N(d.Count));
        }
    }

    private static void AllowedReasons(Section section, ReportInfo r)
    {
        Heading(section, "Why connections were allowed");
        var reasons = r.AllowedReasons ?? [];
        if (reasons.Count == 0)
        {
            Empty(section);
            return;
        }

        var total = Math.Max(1, reasons.Sum(x => x.Count));
        var table = NewTable(section, [("Reason", 4.6, false), ("Connections", 1.3, true), ("Share", 1.1, true)]);
        var i = 0;
        foreach (var reason in reasons)
        {
            AddRow(table, i++, AllowReasons.Label(reason.Reason, null), N(reason.Count), $"{reason.Count * 100.0 / total:0.#}%");
        }
    }

    private static void AllowedPrograms(Section section, ReportInfo r, TimeZoneInfo zone)
    {
        Heading(section, "Programs and services allowed");
        var programs = r.TopAllowedPrograms ?? [];
        if (programs.Count == 0)
        {
            Empty(section);
            return;
        }

        var table = NewTable(section, [("Program or service", 2.55, false), ("Dir.", 0.45, false), ("Allowed", 0.8, true), ("Automatic", 0.85, true), ("Main reason", 1.35, false), ("Last seen", 1.0, false)]);
        var i = 0;
        foreach (var p in programs)
        {
            var direction = p.Direction switch { "in" => "In", "both" => "Both", _ => "Out" };
            var row = AddRow(table, i++, string.Empty, direction, N(p.Count), N(p.Automatic), AllowReasons.Label(p.Reason, p.Direction), Local(p.LastUtc, zone, "g"));
            Program(row.Cells[0], p.App, p.Service, 2.55);
        }
    }

    private static void RulesSection(Section section, ReportPdfInput input)
    {
        Heading(section, "Your rules at the time of the report");
        var mode = section.AddParagraph();
        mode.AddText($"Mode: {ModeName(input.Mode)}. ");
        mode.AddText(input.Mode == "learning"
            ? "Programs without a rule may connect."
            : "Programs without a rule are blocked when they connect out.");

        var programs = input.Rules.Where(r => r.Kind == nameof(FilterKind.AppRule))
            .GroupBy(r => (r.App?.ToUpperInvariant(), r.Action, r.Direction)).Select(g => g.First())
            .OrderBy(r => r.Action).ThenBy(r => KnownApps.DisplayName(r.App), StringComparer.CurrentCultureIgnoreCase).ToList();
        Subheading(section, $"Programs ({programs.Count})");
        if (programs.Count == 0)
        {
            Empty(section);
        }
        else
        {
            var table = NewTable(section, [("Action", 0.8, false), ("Direction", 0.9, false), ("Program", 4.0, false), ("Until", 1.3, false)]);
            var i = 0;
            foreach (var rule in programs)
            {
                var row = AddRow(table, i++, Action(rule.Action), Direction(rule.Direction), string.Empty,
                    rule.ExpiresUtc is DateTime until ? Local(until, input.Zone, "g") : "always");
                ColorAction(row.Cells[0], rule.Action);
                Program(row.Cells[2], rule.App, null, 4.0);
            }
        }

        var net = input.Rules.Where(r => r.Kind == nameof(FilterKind.NetRule))
            .GroupBy(r => (r.Action, r.Direction, r.Protocol, r.Ports, r.Addresses, r.App?.ToUpperInvariant())).Select(g => g.First())
            .OrderBy(r => r.Action).ThenBy(r => r.Summary, StringComparer.CurrentCultureIgnoreCase).ToList();
        Subheading(section, $"Ports and addresses ({net.Count})");
        if (net.Count == 0)
        {
            Empty(section);
        }
        else
        {
            var table = NewTable(section, [("Action", 0.8, false), ("Direction", 0.9, false), ("Rule", 2.6, false), ("Program", 2.7, false)]);
            var i = 0;
            foreach (var rule in net)
            {
                var row = AddRow(table, i++, Action(rule.Action), Direction(rule.Direction), rule.Summary ?? rule.Name, string.Empty);
                ColorAction(row.Cells[0], rule.Action);
                if (rule.App is null)
                {
                    row.Cells[3].AddParagraph("Any program");
                }
                else
                {
                    Program(row.Cells[3], rule.App, null, 2.7);
                }
            }
        }

        var services = input.Rules.Where(r => r.Kind == nameof(FilterKind.ServiceRule))
            .GroupBy(r => (r.Service?.ToUpperInvariant(), r.Action, r.Direction)).Select(g => g.First())
            .OrderBy(r => r.Action).ThenBy(r => r.Service, StringComparer.CurrentCultureIgnoreCase).ToList();
        Subheading(section, $"Windows services ({services.Count})");
        if (services.Count == 0)
        {
            Empty(section);
        }
        else
        {
            var table = NewTable(section, [("Action", 0.8, false), ("Direction", 0.9, false), ("Service", 5.3, false)]);
            var i = 0;
            foreach (var rule in services)
            {
                var row = AddRow(table, i++, Action(rule.Action), Direction(rule.Direction), rule.Service ?? "?");
                ColorAction(row.Cells[0], rule.Action);
            }
        }

        Subheading(section, "Automatic rules");
        var auto = NewTable(section, [("Rule", 4.3, false), ("State", 2.7, false)]);
        var k = 0;
        foreach (var a in input.AutoRules)
        {
            var name = a.Name == AutoRulePolicy.WindowsKernel ? "Windows kernel (System)" : "Windows services (svchost.exe)";
            AddRow(auto, k++, name, !a.Enabled ? "Off" : a.Active ? "On" : "On in Ask and Allow-list modes");
        }

        AddRow(auto, k++, "Local traffic (loopback)", "Always allowed");
        AddRow(auto, k, "Inbound connections", "Left to Windows Firewall unless you add inbound rules");
    }

    // ---- building blocks ----

    private static void Heading(Section section, string text)
    {
        var p = section.AddParagraph(text);
        p.Style = "Section";
    }

    private static void Subheading(Section section, string text)
    {
        var p = section.AddParagraph(text);
        p.Style = "Subsection";
    }

    private static void Empty(Section section)
    {
        var p = section.AddParagraph("Nothing in this period.");
        p.Style = "Note";
    }

    /// <summary>A table with fixed column widths (inches); the heading row repeats on every page.</summary>
    private static Table NewTable(Section section, (string Header, double Inches, bool Right)[] columns, bool header = true)
    {
        var table = section.AddTable();
        table.Style = "Cell";
        table.Borders.Width = Unit.FromPoint(0.5);
        table.Borders.Color = Line;
        table.Borders.Left.Visible = false;
        table.Borders.Right.Visible = false;
        table.LeftPadding = Unit.FromPoint(4);
        table.RightPadding = Unit.FromPoint(4);
        table.TopPadding = Unit.FromPoint(3);
        table.BottomPadding = Unit.FromPoint(3);
        foreach (var (_, inches, right) in columns)
        {
            var column = table.AddColumn(Unit.FromInch(inches));
            column.Format.Alignment = right ? ParagraphAlignment.Right : ParagraphAlignment.Left;
        }

        if (header)
        {
            var row = table.AddRow();
            row.HeadingFormat = true;
            row.Shading.Color = HeadShade;
            row.Format.Font.Bold = true;
            row.Format.Font.Color = Ink;
            row.KeepWith = 1;
            for (var i = 0; i < columns.Length; i++)
            {
                row.Cells[i].AddParagraph(columns[i].Header);
            }
        }

        return table;
    }

    private static Row AddRow(Table table, int index, params string[] cells)
    {
        var row = table.AddRow();
        row.VerticalAlignment = MigraDoc.DocumentObjectModel.Tables.VerticalAlignment.Center;
        if (index % 2 == 1)
        {
            row.Shading.Color = Zebra;
        }

        for (var i = 0; i < cells.Length; i++)
        {
            if (cells[i].Length > 0)
            {
                row.Cells[i].AddParagraph(cells[i]);
            }
        }

        return row;
    }

    /// <summary>The program's name in bold, its service, and its path in small type, wrapped to the column.</summary>
    private static void Program(Cell cell, string? app, string? service, double inches)
    {
        var p = cell.AddParagraph();
        var name = string.IsNullOrEmpty(service) ? KnownApps.DisplayName(app) : $"Service: {service}";
        p.AddFormattedText(name, TextFormat.Bold);
        if (string.IsNullOrEmpty(app) || KnownApps.IsKernel(app) || app == name)
        {
            return;
        }

        foreach (var line in TextWrap.Path(app, (int)(inches * 17)))
        {
            p.AddLineBreak();
            var text = p.AddFormattedText(line);
            text.Size = Unit.FromPoint(7.5);
            text.Color = Muted;
        }
    }

    private static void ColorAction(Cell cell, string? action)
    {
        cell.Format.Font.Bold = true;
        cell.Format.Font.Color = action == "allow" ? Ice : Fire;
    }

    private static string Action(string? action) => action == "allow" ? "Allow" : action == "block" ? "Block" : action ?? "?";

    private static string Direction(string? direction) => direction switch { "in" => "Inbound", "both" => "Both", "out" => "Outbound", _ => "?" };

    private static string ModeName(string mode) => mode switch { "ask" => "Ask", "allowlist" => "Allow-list", _ => "Learning" };

    private static string PeriodName(string period) => period switch
    {
        ReportBuilder.Day => "last 24 hours",
        ReportBuilder.Month => "last 30 days",
        _ => "last 7 days",
    };

    private static string N(int value) => value.ToString("N0", CultureInfo.CurrentCulture);

    private static string Local(DateTime utc, TimeZoneInfo zone, string format) =>
        TimeZoneInfo.ConvertTimeFromUtc(DateTime.SpecifyKind(utc, DateTimeKind.Utc), zone).ToString(format, CultureInfo.CurrentCulture);
}
