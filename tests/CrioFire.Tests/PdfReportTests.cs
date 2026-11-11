using CrioFire.Core;
using CrioFire.Core.Api;
using CrioFire.Reporting;
using PdfSharp.Pdf.IO;

namespace CrioFire.Tests;

/// <summary>The PDF report: product and company named, and long reports split over as many pages as they need.</summary>
public class PdfReportTests
{
    private static ReportPdfInput Input(int rules, int programs)
    {
        var now = new DateTime(2026, 11, 11, 18, 0, 0, DateTimeKind.Utc);
        var events = new List<LoggedEvent>();
        for (var i = 0; i < programs; i++)
        {
            var app = $@"C:\Program Files\Some Vendor With A Long Name\Product {i}\bin\x64\program-with-a-long-file-name-{i}.exe";
            events.Add(new LoggedEvent(now.AddHours(-i % 100), app, "TCP", $"203.0.113.{i % 250}:443", "out", i % 3 == 0 ? "AppRule" : "DefaultBlock"));
            events.Add(new LoggedEvent(now.AddHours(-i % 100), app, "TCP", "198.51.100.7", "out", null, Allowed: true, Count: 5 + i, Reason: i % 2 == 0 ? "Rule" : "NoRule", Port: 443));
        }

        var report = ReportBuilder.Build(events, ReportBuilder.Week, now, TimeZoneInfo.Utc);
        var ruleList = Enumerable.Range(0, rules)
            .Select(i => new RuleInfo((ulong)i, "AppRule", i % 2 == 0 ? "allow" : "block", "out", $@"C:\Apps\Folder {i}\tool-{i}.exe", "outbound IPv4", $"r{i}"))
            .Append(new RuleInfo(9999, "NetRule", "block", "in", null, "inbound IPv4", "n", Protocol: "tcp", Ports: "445", Summary: "TCP · local port 445"))
            .ToList();
        return new ReportPdfInput(report, TimeZoneInfo.Utc, "TEST-PC", "ask", "0.1.0-test", ruleList,
            [new AutoRuleInfo("svchost", true, true), new AutoRuleInfo("system", false, false)], GeneratedUtc: now);
    }

    /// <summary>The WPF font system is used to measure text; give it an STA thread like the app's.</summary>
    private static byte[] BuildOnSta(ReportPdfInput input)
    {
        byte[]? result = null;
        Exception? error = null;
        var thread = new Thread(() =>
        {
            try
            {
                result = ReportPdf.Build(input);
            }
            catch (Exception ex)
            {
                error = ex;
            }
        });
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        thread.Join();
        return error is null ? result! : throw new InvalidOperationException("Building the PDF failed.", error);
    }

    [Fact]
    public void ALongReportSplitsOverManyPagesAndNamesTheProductAndCompany()
    {
        var bytes = BuildOnSta(Input(rules: 300, programs: 60));
        Assert.Equal("%PDF", System.Text.Encoding.ASCII.GetString(bytes, 0, 4));

        using var pdf = PdfReader.Open(new MemoryStream(bytes), PdfDocumentOpenMode.Import);
        Assert.True(pdf.PageCount >= 6, $"Expected a long report on many pages, got {pdf.PageCount}.");
        Assert.Contains("CrioFire Private Firewall", pdf.Info.Title, StringComparison.Ordinal);
        Assert.Equal("CrioSoft LLC", pdf.Info.Author);
    }

    [Fact]
    public void AnEmptyReportIsStillAValidDocument()
    {
        var input = Input(rules: 0, programs: 0);
        var bytes = BuildOnSta(input);
        using var pdf = PdfReader.Open(new MemoryStream(bytes), PdfDocumentOpenMode.Import);
        Assert.InRange(pdf.PageCount, 1, 3);
    }

    [Fact]
    public void TheDocumentHasEverySection()
    {
        var document = ReportPdf.Compose(Input(rules: 3, programs: 3));
        var text = string.Join("\n", document.Sections[0]!.Elements.OfType<MigraDoc.DocumentObjectModel.Paragraph>()
            .Select(p => string.Concat(p.Elements.OfType<MigraDoc.DocumentObjectModel.Text>().Select(t => t.Content))));
        foreach (var heading in new[] { "Summary", "Day by day", "Programs blocked most", "Destinations blocked most", "Why connections were allowed",
                     "Programs and services allowed", "Destinations allowed most", "Your rules at the time of the report", "Automatic rules" })
        {
            Assert.Contains(heading, text, StringComparison.Ordinal);
        }
    }
}
