using System.Security.Principal;
using CrioFire.Core;

namespace CrioFire.IntegrationTests;

/// <summary>
/// Data used per program against Windows' real network events. Needs the runner's internet
/// connection: the test downloads a page and checks that this process's bytes were counted.
/// </summary>
public sealed class DataUsageTests
{
    [Fact]
    public async Task ThisProcesssDownloadIsCounted()
    {
        Assert.SkipUnless(Environment.GetEnvironmentVariable("CRIOFIRE_INTEGRATION") == "1",
            "Set CRIOFIRE_INTEGRATION=1 to run tests that need administrator rights.");
        Assert.True(IsAdministrator(), "Following network traffic needs an administrator terminal.");

        var me = (uint)Environment.ProcessId;
        var counter = new DataCounter(ProcessPaths.Of);
        long received = 0;
        long seen = 0;
        using var events = new NetworkUsageEvents(t =>
        {
            Interlocked.Increment(ref seen);
            if (t.ProcessId == me && !t.Sent && !t.Loopback)
            {
                Interlocked.Add(ref received, t.Bytes);
            }

            counter.Add(t);
        });
        events.Start();

        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(15) };
        http.DefaultRequestHeaders.UserAgent.ParseAdd("CrioFire-IntegrationTests/1.0");
        string[] pages = ["https://github.com/", "https://www.microsoft.com/", "https://example.com/"];
        var downloaded = 0L;
        var problems = new List<string>();
        for (var i = 0; i < 9 && Interlocked.Read(ref received) < 10_000; i++)
        {
            var page = pages[i % pages.Length];
            try
            {
                // Any answer counts, an error page too: only the bytes matter here.
                using var response = await http.GetAsync(new Uri(page), TestContext.Current.CancellationToken);
                downloaded += (await response.Content.ReadAsByteArrayAsync(TestContext.Current.CancellationToken)).Length;
            }
            catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException && !TestContext.Current.CancellationToken.IsCancellationRequested)
            {
                problems.Add($"{page}: {ex.GetBaseException().Message}");
            }

            await Task.Delay(1000, TestContext.Current.CancellationToken);   // events arrive within about a second
        }

        Assert.True(downloaded > 0, "Every download failed: " + string.Join(" | ", problems) + " | " + InstalledFilters());
        Assert.True(Interlocked.Read(ref received) >= 10_000, $"Only {Interlocked.Read(ref received)} bytes received were counted for this process ({downloaded} downloaded, {Interlocked.Read(ref seen)} send/receive events from all processes).");

        var mine = counter.Take().SingleOrDefault(a => string.Equals(a.App, Environment.ProcessPath, StringComparison.OrdinalIgnoreCase));
        Assert.NotNull(mine);   // counted under this process's program
        Assert.True(mine.Received >= 10_000, $"Only {mine.Received} bytes were counted for {mine.App}.");
        Assert.True(mine.Sent > 0, "Nothing sent was counted (the request itself).");
    }

    /// <summary>For a failure message: CrioFire filters left behind could explain a blocked download.</summary>
    private static string InstalledFilters()
    {
        try
        {
            using var engine = WfpEngine.Open();
            var filters = engine.ListFilters();
            return $"{filters.Count} CrioFire filters installed" + (filters.Count == 0 ? "" : ": " + string.Join(", ", filters.Take(10).Select(f => f.Name)));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException)
        {
            return "filters could not be listed: " + ex.Message;
        }
    }

    private static bool IsAdministrator()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }
}
