using CrioFire.Core;

namespace CrioFire.Service;

/// <summary>
/// Looks for a newer CrioFire once a day, when the check is on (Settings, or criofire updates
/// on|off) and group policy does not turn it off. Only the result is kept (update.json); the app
/// shows a banner with a link to the release page. Nothing is downloaded or installed.
/// </summary>
internal sealed partial class UpdateService(ILogger<UpdateService> logger) : BackgroundService
{
    private static readonly TimeSpan FirstLook = TimeSpan.FromMinutes(2);
    private static readonly TimeSpan LookEvery = TimeSpan.FromMinutes(30);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var store = new UpdateStore(UpdateStore.DefaultFolder);
        try
        {
            await Task.Delay(FirstLook, stoppingToken).ConfigureAwait(false);   // let the PC finish starting
            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    var now = DateTime.UtcNow;
                    if (store.Due(now))
                    {
                        var result = UpdateCheck.Fetch(now, stoppingToken);
                        store.Save(result);
                        if (result.Error is not null)
                        {
                            LogCheckFailed(logger, result.Error);
                        }
                        else if (result.Latest is { } latest && UpdateCheck.IsNewer(latest.Version, UpdateCheck.CurrentVersion))
                        {
                            LogNewVersion(logger, latest.Version, latest.Url);
                        }
                    }
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                {
                    LogCheckFailed(logger, ex.Message);
                }

                await Task.Delay(LookEvery, stoppingToken).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException)
        {
            // Service stopping.
        }
    }

    [LoggerMessage(Level = LogLevel.Information, Message = "CrioFire {Version} is available: {Url}")]
    private static partial void LogNewVersion(ILogger logger, string version, string url);

    [LoggerMessage(Level = LogLevel.Warning, Message = "The update check failed: {Reason}")]
    private static partial void LogCheckFailed(ILogger logger, string reason);
}
