using CrioFire.Core;

namespace CrioFire.Service;

/// <summary>
/// Prototype worker: makes sure CrioFire is registered with the filtering engine at start-up
/// and reports how many rules are active. WFP filters are persistent, so they keep working
/// even if this service stops.
/// </summary>
internal sealed partial class FirewallWorker(ILogger<FirewallWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            using (var engine = WfpEngine.Open())
            {
                if (!engine.IsInstalled())
                {
                    engine.Install();
                    LogInstalled(logger);
                }

                LogStarted(logger, engine.ListFilters().Count);
            }
        }
        catch (WfpException ex)
        {
            LogWfpError(logger, ex);
        }

        // TODO(phase 1): host the local API pipe and subscribe to WFP net events for alerts.
        await Task.Delay(Timeout.Infinite, stoppingToken).ConfigureAwait(false);
    }

    [LoggerMessage(Level = LogLevel.Information, Message = "Registered CrioFire with the Windows Filtering Platform.")]
    private static partial void LogInstalled(ILogger logger);

    [LoggerMessage(Level = LogLevel.Information, Message = "CrioFire service started; {FilterCount} filters active.")]
    private static partial void LogStarted(ILogger logger, int filterCount);

    [LoggerMessage(Level = LogLevel.Error, Message = "Filtering engine call failed.")]
    private static partial void LogWfpError(ILogger logger, Exception exception);
}
