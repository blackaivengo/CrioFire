using CrioFire.Core;

namespace CrioFire.Service;

/// <summary>
/// Data used per program: follows every send and receive (<see cref="NetworkUsageEvents"/>), sums
/// them per program (<see cref="DataCounter"/>) and keeps per-day totals in data-usage.json
/// (<see cref="DataUsageStore"/>), saved every few seconds while there is traffic. Clears the
/// counts when the app or command line asks.
/// </summary>
internal sealed partial class UsageService(ILogger<UsageService> logger) : BackgroundService
{
    private static readonly TimeSpan CollectEvery = TimeSpan.FromSeconds(2);
    private static readonly TimeSpan SaveEvery = TimeSpan.FromSeconds(10);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var store = new DataUsageStore(DataUsageStore.DefaultPath);
        var counter = new DataCounter(ProcessPaths.Of);
        using var events = new NetworkUsageEvents(counter.Add);
        try
        {
            events.Start();
            LogCounting(logger);
        }
        catch (Exception ex) when (ex is IOException or PlatformNotSupportedException)
        {
            LogNotCounting(logger, ex);
            return;
        }

        var days = Load(store);
        var dirty = false;
        var lastSave = DateTime.UtcNow;
        try
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                await Task.Delay(CollectEvery, stoppingToken).ConfigureAwait(false);
                var counts = counter.Take();
                try
                {
                    if (store.ResetRequested)
                    {
                        store.CompleteReset();
                        days = [];
                        dirty = false;
                        LogReset(logger);
                        continue;
                    }

                    if (counts.Count > 0)
                    {
                        days = DataUsageStore.Merge(days, DateOnly.FromDateTime(DateTime.Now), counts);
                        dirty = true;
                    }

                    if (dirty && DateTime.UtcNow - lastSave >= SaveEvery)
                    {
                        store.Save(days);
                        dirty = false;
                        lastSave = DateTime.UtcNow;
                    }
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                {
                    LogSaveFailed(logger, ex);   // try again on the next round
                }
            }
        }
        catch (OperationCanceledException)
        {
            // Service stopping.
        }

        var rest = counter.Take();
        if (dirty || rest.Count > 0)
        {
            try
            {
                store.Save(DataUsageStore.Merge(days, DateOnly.FromDateTime(DateTime.Now), rest));
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                LogSaveFailed(logger, ex);
            }
        }
    }

    private static List<UsageDay> Load(DataUsageStore store)
    {
        if (store.ResetRequested)
        {
            store.CompleteReset();
            return [];
        }

        return store.Load();
    }

    [LoggerMessage(Level = LogLevel.Information, Message = "Counting data used per program.")]
    private static partial void LogCounting(ILogger logger);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Cannot follow network traffic; data used per program is not counted.")]
    private static partial void LogNotCounting(ILogger logger, Exception exception);

    [LoggerMessage(Level = LogLevel.Information, Message = "Data counts cleared.")]
    private static partial void LogReset(ILogger logger);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Could not save data used per program.")]
    private static partial void LogSaveFailed(ILogger logger, Exception exception);
}
