using CrioFire.Core;
using CrioFire.Core.Management;

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

    /// <summary>How often allowed programs are checked against the files the user allowed.</summary>
    private static readonly TimeSpan IdentityInterval = TimeSpan.FromSeconds(30);

    /// <summary>How often Store app rules are checked for app updates (a new version folder).</summary>
    private static readonly TimeSpan PackageInterval = TimeSpan.FromSeconds(60);

    /// <summary>How often the rules are compared with the last backup (a new backup only when they changed).</summary>
    private static readonly TimeSpan BackupInterval = TimeSpan.FromMinutes(5);

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
            using var licenseKey = LicenseKeys.ProductPublicKey();
            var identities = new IdentityGuard(new ProgramIdentityStore(ProgramIdentityStore.DefaultPath), new AuthenticodeSignatures());
            var nextIdentityCheck = DateTime.UtcNow;
            var nextPackageCheck = DateTime.UtcNow;
            var packagesSeen = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            var backups = new RuleBackupStore(RuleBackupStore.DefaultFolder);
            var nextBackup = DateTime.UtcNow + TimeSpan.FromMinutes(1);
            string? lastBackup = null;
            var links = new ServerLinkStore(ServerLinkStore.DefaultPath);
            var nextCheckin = DateTime.UtcNow + TimeSpan.FromSeconds(10);
            var checkinEvery = ServerDefaults.CheckinInterval(ServerDefaults.CheckinSeconds);
            Task<CheckinOutcome?>? checkin = null;
            var policies = new ManagedPolicyStore(ManagedPolicyStore.DefaultPath);

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

                    // Managed PCs send the company's CrioFire Server a small state report every few
                    // minutes (the server sets how often). Connections go only when an administrator
                    // asks for them. The check-in runs beside this loop, so a slow or unreachable
                    // server never delays the firewall's work.
                    if (checkin is { IsCompletedSuccessfully: true } done && done.Result is { } outcome)
                    {
                        checkin = null;
                        checkinEvery = outcome.Interval;
                        ApplyPolicy(engine, links, policies, outcome, backups, temporaryRules, now);
                    }

                    if (now >= nextCheckin && checkin is null or { IsCompleted: true })
                    {
                        nextCheckin = now + checkinEvery;
                        checkin = null;
                        if (links.Load() is { } link)
                        {
                            var license = LicenseKeys.Check(new LicenseStore(LicenseStore.DefaultPath).Key, now, licenseKey);
                            var report = CheckinReports.Build(engine, identities.Store.Changed().Count,
                                new TamperProtection(TamperProtection.DefaultPath).RequireAdmin,
                                license.State,
                                link.PolicyId,
                                link.PolicyVersion,
                                license.LicenseId);
                            checkin = CheckinAsync(links, link, report, log, allowedLog, stoppingToken);
                        }
                    }

                    if (allowedWorks)
                    {
                        try
                        {
                            var allowed = recentAllowed.KeepNew(engine.ReadAllowedConnections(from, now, paths), now);
                            if (allowed.Count > 0)
                            {
                                allowedLog.AppendSummaries(AllowedSummary.Aggregate(NameServices(allowed, engine.ListFilters())));
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

                    // Store apps move to a new folder with every update; renew their rules to match.
                    if (now >= nextPackageCheck)
                    {
                        nextPackageCheck = now + PackageInterval;
                        try
                        {
                            foreach (var package in StoreApps.Refresh(engine, packagesSeen))
                            {
                                LogPackageRenewed(logger, package);
                            }
                        }
                        catch (ArgumentException ex)
                        {
                            LogPollError(logger, ex);
                        }
                    }

                    // Automatic backups: days of rule-making must not be lost to one wrong click.
                    if (now >= nextBackup)
                    {
                        nextBackup = now + BackupInterval;
                        lastBackup ??= backups.LatestFingerprint() ?? string.Empty;
                        var rules = RuleBackup.Export(engine, temporaryRules, now, new DomainRuleStore(DomainRuleStore.DefaultPath));
                        var fingerprint = RuleBackup.Fingerprint(rules);
                        if (rules.Count > 0 && fingerprint != lastBackup)
                        {
                            var saved = backups.Save(rules, "auto");
                            LogBackedUp(logger, saved);
                            lastBackup = fingerprint;
                        }
                    }

                    // A program put in place of an allowed one, or a tampered copy, loses the permission.
                    if (now >= nextIdentityCheck)
                    {
                        nextIdentityCheck = now + IdentityInterval;
                        foreach (var changed in identities.Enforce(engine, now, temporaryRules))
                        {
                            LogProgramChanged(logger, changed.App, changed.WasPublisher ?? "unsigned", changed.NowPublisher ?? "unsigned", changed.Blocked);
                        }
                    }
                }
                catch (Exception ex) when (ex is WfpException or IOException or UnauthorizedAccessException)
                {
                    LogPollError(logger, ex);
                }
            }
        }
    }

    /// <summary>
    /// One check-in with the CrioFire Server, and the connections when an administrator asked for
    /// them. The result is kept in server.json for the app and the command line. Returns the
    /// interval the server wants until the next check-in, or null after a failure.
    /// </summary>
    private async Task<CheckinOutcome?> CheckinAsync(ServerLinkStore links, ServerLink link, CheckinReport report, TrafficLog blockedLog, TrafficLog allowedLog, CancellationToken stoppingToken)
    {
        try
        {
            using var client = new ManagementClient(link.Url, link.Fingerprint);
            var answer = await client.CheckinAsync(link, report, stoppingToken).ConfigureAwait(false);
            if (answer.Activity is { } asked)
            {
                var upload = CheckinReports.Activity(asked, blockedLog, allowedLog, DateTime.UtcNow);
                await client.UploadActivityAsync(link, upload, stoppingToken).ConfigureAwait(false);
                LogActivitySent(logger, upload.Page.Items.Count, link.Url);
            }

            // The organization's license, so nobody types the key on each PC.
            if (answer.LicenseKey is { } key)
            {
                using var publicKey = LicenseKeys.ProductPublicKey();
                try
                {
                    if (CheckinReports.AcceptLicense(key, new LicenseStore(LicenseStore.DefaultPath), publicKey, DateTime.UtcNow))
                    {
                        LogLicenseReceived(logger, link.Url);
                    }
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                {
                    LogPollError(logger, ex);   // the check-in itself worked; the key comes again next time
                }
            }

            SaveIfStillEnrolled(links, link with { LastCheckinUtc = DateTime.UtcNow, LastError = null });
            return new CheckinOutcome(link.DeviceId, ServerDefaults.CheckinInterval(answer.NextCheckinSeconds), answer.PolicyId, answer.PolicyVersion, answer.Policy);
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or IOException)
        {
            if (!stoppingToken.IsCancellationRequested)
            {
                SaveIfStillEnrolled(links, link with { LastError = ex.Message });
                LogCheckinFailed(logger, link.Url, ex.Message);
            }

            return null;
        }
    }

    /// <summary>
    /// Puts the organization's policy in force when the server sent a new one, or removes the
    /// organization's rules when the PC no longer has a policy. Runs on the main loop, which owns
    /// the filtering-engine session.
    /// </summary>
    private void ApplyPolicy(WfpEngine engine, ServerLinkStore links, ManagedPolicyStore policies, CheckinOutcome outcome,
        RuleBackupStore backups, TemporaryRuleStore temporaryRules, DateTime now)
    {
        if (links.Load() is not { } link || link.DeviceId != outcome.DeviceId)
        {
            return;
        }

        try
        {
            if (outcome.Policy is { } policy)
            {
                var rules = ManagedPolicies.Apply(engine, policy, backups, temporaryRules, new TamperProtection(TamperProtection.DefaultPath), now,
                    new DomainRuleStore(DomainRuleStore.DefaultPath));
                policies.Save(policy);
                links.Save(link with { PolicyId = policy.Id, PolicyVersion = policy.Version });
                LogPolicyApplied(logger, policy.Name, policy.Version, rules);
            }
            else if (outcome.PolicyId is null && link.PolicyId is not null)
            {
                ManagedPolicies.Clear(engine, policies, new DomainRuleStore(DomainRuleStore.DefaultPath));
                links.Save(link with { PolicyId = null, PolicyVersion = 0 });
                LogPolicyRemoved(logger);
            }
        }
        catch (Exception ex) when (ex is WfpException or ArgumentException or IOException or InvalidOperationException)
        {
            links.Save(link with { LastError = $"Could not apply the organization's policy: {ex.Message}" });
            LogPollError(logger, ex);
        }
    }

    /// <summary>What one check-in brought back.</summary>
    private sealed record CheckinOutcome(string DeviceId, TimeSpan Interval, string? PolicyId, int PolicyVersion, ManagedPolicy? Policy);

    /// <summary>Records a check-in result, unless the PC was unenrolled or enrolled elsewhere meanwhile.</summary>
    private static void SaveIfStillEnrolled(ServerLinkStore links, ServerLink link)
    {
        if (links.Load()?.DeviceId == link.DeviceId)
        {
            links.Save(link);
        }
    }

    /// <summary>For svchost.exe connections: finds which service owns the socket, when it is still open.</summary>
    private static IReadOnlyList<AllowedConnection> NameServices(IReadOnlyList<AllowedConnection> allowed, IReadOnlyList<CrioFireFilter> filters)
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

        // With the service known, a service rule may turn out to be what allowed it.
        return allowed
            .Select(a => KnownApps.IsServiceHost(a.AppPath)
                ? a with { Service = ServiceAttribution.Find(table, services, a.Protocol, a.Local, a.Remote) }
                : a)
            .Select(a => a.Service is null ? a : a with { Rule = AllowReasons.Resolve(filters, a) })
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

    [LoggerMessage(Level = LogLevel.Information, Message = "Applied the organization's policy {Name} (version {Version}, {Rules} rules).")]
    private static partial void LogPolicyApplied(ILogger logger, string name, int version, int rules);

    [LoggerMessage(Level = LogLevel.Information, Message = "This PC no longer has an organization policy; its rules were removed.")]
    private static partial void LogPolicyRemoved(ILogger logger);

    [LoggerMessage(Level = LogLevel.Information, Message = "Sent {Rows} rows of connections to the CrioFire Server {Url}, as an administrator asked.")]
    private static partial void LogActivitySent(ILogger logger, int rows, string url);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Could not check in with the CrioFire Server {Url}: {Error}")]
    private static partial void LogCheckinFailed(ILogger logger, string url, string error);

    [LoggerMessage(Level = LogLevel.Information, Message = "Received the organization's license from {Url}")]
    private static partial void LogLicenseReceived(ILogger logger, string url);

    [LoggerMessage(Level = LogLevel.Information, Message = "Saved a backup of the rules: {Name}.")]
    private static partial void LogBackedUp(ILogger logger, string name);

    [LoggerMessage(Level = LogLevel.Debug, Message = "Renewed the rules of the Store app {Package}.")]
    private static partial void LogPackageRenewed(ILogger logger, string package);

    [LoggerMessage(Level = LogLevel.Warning, Message = "{App} changed since it was allowed (publisher {Was} -> {Now}); blocked: {Blocked}.")]
    private static partial void LogProgramChanged(ILogger logger, string app, string was, string now, bool blocked);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Reading blocked connections failed; will retry.")]
    private static partial void LogPollError(ILogger logger, Exception exception);
}
