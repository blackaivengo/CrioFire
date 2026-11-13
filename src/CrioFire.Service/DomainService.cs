using System.Net;
using System.Net.Sockets;
using System.Threading.Channels;
using CrioFire.Core;

namespace CrioFire.Service;

/// <summary>
/// Domain rules: follows Windows' name lookups (<see cref="DnsClientEvents"/>) and keeps an address
/// filter for every address a lookup returned for a name a rule covers (<see cref="DomainKeeper"/>).
/// Notices rules added or removed through the API within a few seconds, and drops addresses no
/// lookup returned for an hour. Uses its own filtering-engine session; all filter changes happen on
/// this service's loop.
/// </summary>
internal sealed partial class DomainService(ILogger<DomainService> logger) : BackgroundService
{
    private static readonly TimeSpan RulesCheck = TimeSpan.FromSeconds(2);
    private static readonly TimeSpan SweepEvery = TimeSpan.FromMinutes(1);

    private volatile DomainRule[] _rules = [];

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            using var engine = WfpEngine.Open();
            var store = new DomainRuleStore(DomainRuleStore.DefaultPath);
            var keeper = new DomainKeeper(engine, Resolve);
            var changed = store.Changed;
            _rules = [.. store.List()];
            keeper.Reset(_rules, DateTime.UtcNow);

            var lookups = Channel.CreateBounded<DnsLookup>(new BoundedChannelOptions(4096) { SingleReader = true, FullMode = BoundedChannelFullMode.DropOldest });
            using var events = new DnsClientEvents();
            events.Lookup += lookup =>
            {
                // Only lookups some rule covers go to the loop; the rest are dropped here, unread.
                var rules = _rules;
                if (rules.Length > 0 && rules.Any(r => lookup.AllNames.Any(r.Covers)))
                {
                    lookups.Writer.TryWrite(lookup);
                }
            };

            try
            {
                events.Start();
                LogWatching(logger);
            }
            catch (Exception ex) when (ex is IOException or PlatformNotSupportedException)
            {
                // Rules still apply to the addresses their domains resolve to now; they just do not follow changes.
                LogNoLookups(logger, ex);
            }

            var lastSweep = DateTime.UtcNow;
            while (!stoppingToken.IsCancellationRequested)
            {
                using var wait = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
                wait.CancelAfter(RulesCheck);
                try
                {
                    var lookup = await lookups.Reader.ReadAsync(wait.Token).ConfigureAwait(false);
                    var added = keeper.Observe(lookup, DateTime.UtcNow);
                    while (lookups.Reader.TryRead(out var more))
                    {
                        added += keeper.Observe(more, DateTime.UtcNow);
                    }

                    if (added > 0)
                    {
                        LogAdded(logger, added, lookup.Name);
                    }
                }
                catch (OperationCanceledException) when (!stoppingToken.IsCancellationRequested)
                {
                    // Nothing to read for a while: time for the periodic checks.
                }

                var now = DateTime.UtcNow;
                if (store.Changed != changed)
                {
                    changed = store.Changed;
                    _rules = [.. store.List()];
                    keeper.Update(_rules, now);
                    LogRules(logger, _rules.Length);
                }

                if (now - lastSweep >= SweepEvery)
                {
                    lastSweep = now;
                    keeper.Sweep(now);
                }
            }
        }
        catch (OperationCanceledException)
        {
            // Service stopping.
        }
        catch (Exception ex) when (ex is WfpException or IOException or UnauthorizedAccessException)
        {
            LogFailed(logger, ex);
        }
    }

    /// <summary>What a domain resolves to now (used when a rule is added and at start).</summary>
    private static IPAddress[] Resolve(string domain)
    {
        try
        {
            return Dns.GetHostAddresses(domain);
        }
        catch (ArgumentException)
        {
            return [];
        }
        catch (SocketException)
        {
            return [];
        }
    }

    [LoggerMessage(Level = LogLevel.Information, Message = "Following name lookups for domain rules.")]
    private static partial void LogWatching(ILogger logger);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Cannot follow name lookups; domain rules use the addresses their domains resolve to when added.")]
    private static partial void LogNoLookups(ILogger logger, Exception exception);

    [LoggerMessage(Level = LogLevel.Debug, Message = "Domain rules: {Count} address filter(s) added after looking up {Name}.")]
    private static partial void LogAdded(ILogger logger, int count, string name);

    [LoggerMessage(Level = LogLevel.Information, Message = "Domain rules changed: {Count} rule(s).")]
    private static partial void LogRules(ILogger logger, int count);

    [LoggerMessage(Level = LogLevel.Error, Message = "Domain rules stopped working.")]
    private static partial void LogFailed(ILogger logger, Exception exception);
}
