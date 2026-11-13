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

        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(20) };
        var downloaded = 0L;
        for (var i = 0; i < 10 && Interlocked.Read(ref received) < 10_000; i++)
        {
            try
            {
                downloaded += (await http.GetByteArrayAsync(new Uri("https://www.microsoft.com/"), TestContext.Current.CancellationToken)).Length;
            }
            catch (HttpRequestException)
            {
                // try again
            }

            await Task.Delay(1000, TestContext.Current.CancellationToken);   // events arrive within about a second
        }

        Assert.True(downloaded > 0, "The download failed: the runner needs an internet connection.");
        Assert.True(Interlocked.Read(ref received) >= 10_000, $"Only {Interlocked.Read(ref received)} bytes received were counted for this process ({downloaded} downloaded, {Interlocked.Read(ref seen)} send/receive events from all processes).");

        var mine = counter.Take().SingleOrDefault(a => string.Equals(a.App, Environment.ProcessPath, StringComparison.OrdinalIgnoreCase));
        Assert.NotNull(mine);   // counted under this process's program
        Assert.True(mine.Received >= 10_000, $"Only {mine.Received} bytes were counted for {mine.App}.");
        Assert.True(mine.Sent > 0, "Nothing sent was counted (the request itself).");
    }

    private static bool IsAdministrator()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }
}
