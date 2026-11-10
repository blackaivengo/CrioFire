using CrioFire.Core;

namespace CrioFire.Service;

/// <summary>
/// The service's main loop: makes sure CrioFire is registered with the filtering engine, then
/// every <see cref="PollInterval"/> reads the connections CrioFire blocked and appends them to the
/// traffic log (%ProgramData%\criofire\blocked.log), and every connection that was allowed, with
/// the reason, summed per minute to allowed.log. WFP filters are persistent, so blocking keeps
/// working even while this service is stopped.
/// </summary>
internal sealed partial class FirewallWorker(ILogger<FirewallWorker> logger) : BackgroundService
{
    private static readonly TimeSpan PollInterval = TimeSpan.FromSeconds(2);
    private static readonly TimeSpan Overlap = TimeSpan.FromSeconds(10);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        WfpEngine engine;
        try
        {
            engine = WfpEngine.Open();
            if (!engine.IsInstalled())
            {
                engine.Install();
                LogInstalled(logger);
            }
            else
            {
                engine.EnableNetEventCollection();
            }

            var filterCount = engine.ListFilters().Count;
            LogStarted(logger, filterCount);
        }
        catch (WfpException ex)
        {
            LogWfpError(logger, ex);
            await Task.Delay(Timeout.Infinite, stoppingToken).ConfigureAwait(false);
            return;
        }

        using (engine)
        {
            var log = new TrafficLog(TrafficLog.DefaultPath);
            var allowedLog = new TrafficLog(TrafficLog.AllowedPath);
            var paths = NtPathMapper.FromSystem();
            var started = DateTime.UtcNow;
            var recent = new RecentEvents(Overlap);
            var recentAllowed = new RecentEvents(Overlap);
            var allowedWorks = true;
            var temporaryRules = new TemporaryRuleStore(TemporaryRuleStore.DefaultPath);

            using var timer = new PeriodicTimer(PollInterval);
            while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false))
            {
                try
                {
                    // Re-read a short overlap each time, because the engine can record an event a
                    // moment after its timestamp; RecentEvents drops the ones already logged.
                    var now = DateTime.UtcNow;
                    var from = now - Overlap < started ? started : now - Overlap;
                    var blocked = recent.KeepNew(engine.ReadBlockedConnections(from, now, crioFireOnly: true, paths), now);
                    if (blocked.Count > 0)
                    {
                        log.Append(blocked);
                        LogBlocked(logger, blocked.Count);
                    }

                    if (allowedWorks)
                    {
                        try
                        {
                            var allowed = recentAllowed.KeepNew(engine.ReadAllowedConnections(from, now, paths), now);
                            if (allowed.Count > 0)
                            {
                                allowedLog.AppendSummaries(AllowedSummary.Aggregate(NameServices(allowed)));
                            }
                        }
                        catch (EntryPointNotFoundException ex)
                        {
                            // Windows without FwpmNetEventEnum2: keep blocking, stop trying this.
                            allowedWorks = false;
                            LogAllowedUnavailable(logger, ex);
                        }
                    }

                    // "Allow for 1 hour" and similar: remove rules whose time is up.
                    var expired = temporaryRules.ExpireDue(engine, now);
                    if (expired > 0)
                    {
                        LogExpired(logger, expired);
                    }
                }
                catch (Exception ex) when (ex is WfpException or IOException or UnauthorizedAccessException)
                {
                    LogPollError(logger, ex);
                }
            }
        }
    }

    /// <summary>For svchost.exe connections: finds which service owns the socket, when it is still open.</summary>
    private static IReadOnlyList<AllowedConnection> NameServices(IReadOnlyList<AllowedConnection> allowed)
    {
        if (!allowed.Any(a => KnownApps.IsServiceHost(a.AppPath)))
        {
            return allowed;
        }

        IReadOnlyList<LiveConnection> table;
        IReadOnlyDictionary<int, string[]> services;
        try
        {
            table = ConnectionTable.Read();
            services = WindowsServiceList.ByProcess(WindowsServiceList.Read());
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException)
        {
            return allowed;
        }

        return allowed
            .Select(a => KnownApps.IsServiceHost(a.AppPath)
                ? a with { Service = ServiceAttribution.Find(table, services, a.Protocol, a.Local, a.Remote) }
                : a)
            .ToList();
    }

    [LoggerMessage(Level = LogLevel.Warning, Message = "This Windows version cannot report allowed connections; only blocked ones will be shown.")]
    private static partial void LogAllowedUnavailable(ILogger logger, Exception exception);

    [LoggerMessage(Level = LogLevel.Information, Message = "Registered CrioFire with the Windows Filtering Platform.")]
    private static partial void LogInstalled(ILogger logger);

    [LoggerMessage(Level = LogLevel.Information, Message = "CrioFire service started; {FilterCount} filters active.")]
    private static partial void LogStarted(ILogger logger, int filterCount);

    [LoggerMessage(Level = LogLevel.Error, Message = "Filtering engine call failed.")]
    private static partial void LogWfpError(ILogger logger, Exception exception);

    [LoggerMessage(Level = LogLevel.Debug, Message = "Logged {Count} blocked connections.")]
    private static partial void LogBlocked(ILogger logger, int count);

    [LoggerMessage(Level = LogLevel.Information, Message = "Removed {Count} expired temporary rules.")]
    private static partial void LogExpired(ILogger logger, int count);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Reading blocked connections failed; will retry.")]
    private static partial void LogPollError(ILogger logger, Exception exception);
}
