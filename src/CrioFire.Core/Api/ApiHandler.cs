using System.Reflection;

namespace CrioFire.Core.Api;

/// <summary>
/// Carries out API requests against the filtering engine. Used by the service for pipe clients,
/// and directly by criofire.exe when it runs elevated (so both paths behave identically).
/// Thread-safe: requests are handled one at a time.
/// </summary>
/// <param name="allowedLog">The service's log of allowed connections (allowed.log), for reports and the allowed list.</param>
/// <param name="identities">Checks that allowed programs stay the files the user allowed; null where not used (tests).</param>
/// <param name="backups">Where rule backups are kept (automatic, and before imports and "remove all"); null in tests.</param>
/// <param name="protection">Tamper protection; null means off (tests).</param>
/// <param name="license">The license key entered on this PC; null in tests.</param>
/// <param name="serverLink">The link to a company's CrioFire Server, when this PC is managed; null in tests.</param>
/// <param name="policy">The organization's policy in force, which can stop users from changing rules, the mode or tamper protection.</param>
/// <param name="domainRules">The domain rules (the service turns them into address filters); null where not used (tests).</param>
/// <param name="logSettings">How much connection history the service keeps; null where not used (tests).</param>
public sealed class ApiHandler(WfpEngine engine, TemporaryRuleStore? temporaryRules = null, TrafficLog? trafficLog = null, TrafficLog? allowedLog = null, IdentityGuard? identities = null, RuleBackupStore? backups = null, TamperProtection? protection = null, LicenseStore? license = null, global::CrioFire.Core.Management.ServerLinkStore? serverLink = null, ManagedPolicyStore? policy = null, DomainRuleStore? domainRules = null, DataUsageStore? usage = null, LogSettingsStore? logSettings = null)
{
    private static readonly string Version =
        typeof(ApiHandler).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? "unknown";

    private readonly Lock _gate = new();
    private readonly Lazy<System.Security.Cryptography.ECDsa?> _licenseKey = new(LicenseKeys.ProductPublicKey);

    /// <summary>For callers that are either fully trusted (an elevated command line) or read-only.</summary>
    public ApiResponse Handle(ApiRequest request, bool canWrite) =>
        Handle(request, canWrite ? ClientRights.Administrator : ClientRights.ReadOnly);

    public ApiResponse Handle(ApiRequest request, ClientRights rights)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (ApiOps.IsWrite(request.Op))
        {
            if (rights == ClientRights.ReadOnly)
            {
                return ApiResponse.Failure("Not allowed: changing rules needs an administrator, or CrioFire's own app or command line.");
            }

            if (rights == ClientRights.CrioFireApp && (request.Op == ApiOps.SetProtection || protection?.RequireAdmin == true))
            {
                return ApiResponse.Failure(
                    request.Op == ApiOps.SetProtection
                        ? "Changing tamper protection needs administrator approval."
                        : "Tamper protection is on: changing rules needs administrator approval (approve the prompt in the app, or use an administrator prompt).",
                    ApiOps.ApprovalRequired);
            }

            if (policy?.Load() is { } managed && ManagedRefusal(request, managed) is { } refusal)
            {
                return ApiResponse.Failure(refusal);
            }
        }

        if (request.Op == ApiOps.ResetUsage && rights == ClientRights.ReadOnly)
        {
            return ApiResponse.Failure("Not allowed: clearing the data counts needs CrioFire's own app or command line, or an administrator.");
        }

        if (request.Op is ApiOps.Logs or ApiOps.SetLogs or ApiOps.ClearLogs)
        {
            try
            {
                return Logs(request);
            }
            catch (Exception ex) when (ex is ArgumentException or IOException or UnauthorizedAccessException or InvalidOperationException)
            {
                return ApiResponse.Failure(ex.Message);
            }
        }

        if (request.Op is ApiOps.Report or ApiOps.Allowed or ApiOps.Traffic or ApiOps.Usage or ApiOps.ResetUsage)
        {
            // Reads only the log files, not the engine: no need to hold up other clients.
            try
            {
                return request.Op switch
                {
                    ApiOps.Report => Report(request),
                    ApiOps.Allowed => Allowed(request),
                    ApiOps.Usage => Usage(request, DateOnly.FromDateTime(DateTime.Now)),
                    ApiOps.ResetUsage => ResetUsage(),
                    _ => Traffic(request),
                };
            }
            catch (Exception ex) when (ex is IOException or InvalidOperationException or ArgumentException or UnauthorizedAccessException)
            {
                return ApiResponse.Failure(ex.Message);
            }
        }

        lock (_gate)
        {
            try
            {
                return request.Op switch
                {
                    ApiOps.Status => Status(),
                    ApiOps.List => List(),
                    ApiOps.Events => Events(request),
                    ApiOps.SetRule => SetRule(request),
                    ApiOps.RemoveRules => RemoveRules(request),
                    ApiOps.RemoveFilter => RemoveFilter(request),
                    ApiOps.SetMode => SetMode(request),
                    ApiOps.Panic => Panic(request),
                    ApiOps.AddNetRule => AddNetRule(request),
                    ApiOps.SetServiceRule => SetServiceRule(request),
                    ApiOps.RemoveServiceRules => RemoveServiceRules(request),
                    ApiOps.SetAutoRule => SetAutoRule(request),
                    ApiOps.Changed => new ApiResponse { Ok = true, Changed = identities?.Store.Changed().ToList() ?? [] },
                    ApiOps.Trust => Trust(request),
                    ApiOps.ExportRules => new ApiResponse { Ok = true, RuleSet = RuleBackup.Export(engine, temporaryRules, DateTime.UtcNow, domainRules) },
                    ApiOps.Domains => Domains(),
                    ApiOps.SetDomainRule => SetDomainRule(request),
                    ApiOps.RemoveDomainRule => RemoveDomainRule(request),
                    ApiOps.ImportRules => Import(request.RuleSet ?? throw new ArgumentException("ruleSet is required."), request),
                    ApiOps.SetProtection => SetProtection(request),
                    ApiOps.License => new ApiResponse { Ok = true, License = LicenseKeys.Check(license?.Key, DateTime.UtcNow, _licenseKey.Value) },
                    ApiOps.SetLicense => SetLicense(request),
                    ApiOps.Management => new ApiResponse { Ok = true, Management = serverLink?.Load() is { } link ? global::CrioFire.Core.Management.ManagementInfo.From(link, policy?.Load()) : null },
                    ApiOps.Backups => new ApiResponse { Ok = true, Backups = backups?.List().ToList() ?? [] },
                    ApiOps.RestoreBackup => Import(
                        (backups ?? throw new InvalidOperationException("Backups need the criofire service.")).Load(Required(request.Name, "name")),
                        request with { ImportMode = "replace", WithMode = true }),
                    _ => ApiResponse.Failure($"Unknown operation '{request.Op}'."),
                };
            }
            catch (Exception ex) when (ex is WfpException or IOException or InvalidOperationException or ArgumentException or UnauthorizedAccessException)
            {
                return ApiResponse.Failure(ex.Message);
            }
        }
    }

    private ApiResponse Status()
    {
        var installed = engine.IsInstalled();
        return new ApiResponse
        {
            Ok = true,
            Status = new StatusInfo(
                installed,
                FilterDescriptions.ModeText(installed ? engine.GetMode() : FirewallMode.Learning),
                installed ? engine.ListFilters().Count : 0,
                Version,
                FilterDescriptions.PanicText(installed ? engine.GetPanic() : PanicState.Off),
                identities?.Store.Changed().Count ?? 0,
                protection?.RequireAdmin ?? false),
        };
    }

    private ApiResponse Events(ApiRequest request)
    {
        var minutes = request.Minutes is > 0 and <= 10080 ? request.Minutes.Value : 10;
        var events = engine.ReadBlockedConnections(DateTime.UtcNow.AddMinutes(-minutes), crioFireOnly: request.All != true);
        return new ApiResponse { Ok = true, Events = events.Select(EventInfo.From).ToList() };
    }

    private ApiResponse SetRule(ApiRequest request)
    {
        var action = request.Action?.ToLowerInvariant() switch
        {
            "block" => RuleAction.Block,
            "allow" => RuleAction.Allow,
            _ => throw new ArgumentException("action must be block or allow."),
        };
        var app = KnownApps.Normalize(Required(request.App, "app"));
        var direction = ParseDirection(request.Direction, TrafficDirection.Outbound);
        if (request.ExpiresMinutes is not null && (request.ExpiresMinutes < 1 || request.ExpiresMinutes > 7 * 24 * 60))
        {
            throw new ArgumentException("expiresMinutes must be between 1 and 10080.");
        }

        if (request.ExpiresMinutes is not null && temporaryRules is null)
        {
            throw new InvalidOperationException("Temporary rules need the criofire service.");
        }

        EnsureInstalled();
        var ids = engine.SetAppRule(app, action, direction, ParseNetworks(request.Networks));
        temporaryRules?.Remove(app);
        if (action == RuleAction.Allow)
        {
            identities?.Record(app, DateTime.UtcNow);   // what the user allowed, so a changed file is noticed
        }
        else
        {
            identities?.Store.Forget(app);
        }
        if (request.ExpiresMinutes is int minutes)
        {
            temporaryRules!.Add(new TemporaryRule(app, RuleDescription.DirectionText(direction), DateTime.UtcNow.AddMinutes(minutes)));
        }

        return new ApiResponse { Ok = true, Count = ids.Count };
    }

    private ApiResponse Report(ApiRequest request)
    {
        var period = request.Period ?? ReportBuilder.Day;
        if (!ReportBuilder.IsPeriod(period))
        {
            throw new ArgumentException("period must be 24h, 7d or 30d.");
        }

        if (trafficLog is null)
        {
            throw new InvalidOperationException("Reports need the criofire service, which keeps the traffic log.");
        }

        var now = DateTime.UtcNow;
        var (from, to, _) = ReportBuilder.Window(period, now, TimeZoneInfo.Local);
        var events = TrafficHistory.Read([trafficLog, allowedLog], from - (to - from));   // the period before, for the comparison
        return new ApiResponse { Ok = true, Report = ReportBuilder.Build(events, period, now) };
    }

    private ApiResponse Allowed(ApiRequest request)
    {
        if (allowedLog is null)
        {
            throw new InvalidOperationException("The allowed list needs the criofire service, which records allowed connections.");
        }

        var minutes = request.Minutes is > 0 and <= 43200 ? request.Minutes.Value : 60;
        var events = TrafficHistory.Read(allowedLog, DateTime.UtcNow.AddMinutes(-minutes));
        return new ApiResponse { Ok = true, Allowed = AllowedGroup.From(events, request.IncludeLoopback == true) };
    }

    private ApiResponse Traffic(ApiRequest request)
    {
        if (trafficLog is null && allowedLog is null)
        {
            throw new InvalidOperationException("Traffic history needs the criofire service, which records it.");
        }

        var kind = request.TrafficKind?.ToLowerInvariant() ?? "all";
        if (kind is not ("blocked" or "allowed" or "all"))
        {
            throw new ArgumentException("trafficKind must be blocked, allowed or all.");
        }

        if (request.Why is { Length: > 0 } why && !TrafficQuery.WhyGroups.Contains(why))
        {
            throw new ArgumentException($"why must be one of: {string.Join(", ", TrafficQuery.WhyGroups)}.");
        }

        var minutes = request.Minutes is > 0 and <= 43200 ? request.Minutes.Value : 60;
        var from = DateTime.UtcNow.AddMinutes(-minutes);
        var logs = new List<TrafficLog?>();
        if (kind != "allowed")
        {
            logs.Add(trafficLog);
        }

        if (kind != "blocked")
        {
            logs.Add(allowedLog);
        }

        var filter = new TrafficFilter(
            kind, from, request.Search, request.Why, request.Direction, request.App, request.Service,
            request.IncludeLoopback == true, request.Sort, request.Offset ?? 0, request.Limit ?? 100);
        return new ApiResponse { Ok = true, Traffic = TrafficQuery.Run(TrafficHistory.Read(logs, from), filter) };
    }

    private ApiResponse SetServiceRule(ApiRequest request)
    {
        var action = request.Action?.ToLowerInvariant() switch
        {
            "block" => RuleAction.Block,
            "allow" => RuleAction.Allow,
            _ => throw new ArgumentException("action must be block or allow."),
        };
        var service = Required(request.Service, "service");
        EnsureInstalled();
        var ids = engine.SetServiceRule(service, action, ParseDirection(request.Direction, TrafficDirection.Outbound), ParseNetworks(request.Networks));
        return new ApiResponse { Ok = true, Count = ids.Count };
    }

    private ApiResponse RemoveServiceRules(ApiRequest request)
    {
        var count = engine.RemoveServiceRules(Required(request.Service, "service"), ParseDirection(request.Direction, TrafficDirection.Both));
        return new ApiResponse { Ok = true, Count = count };
    }

    private ApiResponse SetAutoRule(ApiRequest request)
    {
        var name = Required(request.AutoRule, "autoRule").ToLowerInvariant();
        if (!AutoRulePolicy.IsKnown(name))
        {
            throw new ArgumentException($"autoRule must be one of: {string.Join(", ", AutoRulePolicy.Names)}.");
        }

        EnsureInstalled();
        engine.SetAutoRule(name, request.Enabled ?? throw new ArgumentException("enabled is required."));
        return new ApiResponse { Ok = true, AutoRules = AutoRules() };
    }

    /// <summary>
    /// trust: the user checked a changed program and allows it again as it is now, in the
    /// direction its allow rule had.
    /// </summary>
    private ApiResponse Trust(ApiRequest request)
    {
        if (identities is null)
        {
            throw new InvalidOperationException("Checking programs needs the criofire service.");
        }

        var app = KnownApps.Normalize(Required(request.App, "app"));
        var changed = identities.Store.Changed(app);
        var direction = ParseDirection(request.Direction ?? changed?.Direction, TrafficDirection.Outbound);
        EnsureInstalled();
        var networks = engine.ListFilters().FirstOrDefault(f => !f.Managed && f.Rule is not null
            && string.Equals(f.Rule.AppPath, app, StringComparison.OrdinalIgnoreCase))?.Rule!.Networks ?? NetworkProfiles.Any;
        var ids = engine.SetAppRule(app, RuleAction.Allow, direction, networks);   // on the same networks as before
        identities.Record(app, DateTime.UtcNow);
        return new ApiResponse { Ok = true, Count = ids.Count };
    }

    /// <summary>
    /// importRules / restoreBackup: compares or applies a rules file. A backup of the rules in
    /// force is saved first, so any import can be undone with restoreBackup.
    /// </summary>
    private ApiResponse Import(RuleSet set, ApiRequest request)
    {
        if (RuleBackup.Validate(set) is { } invalid)
        {
            throw new ArgumentException(invalid);
        }

        var mode = request.ImportMode?.ToLowerInvariant() switch
        {
            null or "" or "merge" => ImportMode.Merge,
            "replace" => ImportMode.Replace,
            _ => throw new ArgumentException("importMode must be merge or replace."),
        };
        var now = DateTime.UtcNow;
        var withMode = request.WithMode == true;
        if (request.DryRun == true)
        {
            return new ApiResponse { Ok = true, Plan = RuleBackup.Plan(RuleBackup.Export(engine, temporaryRules, now, domainRules), set, mode, File.Exists, withMode) };
        }

        EnsureInstalled();
        Backup("before-import");
        var plan = RuleBackup.Apply(engine, set, mode, temporaryRules, withMode, now, domainRules);
        return new ApiResponse { Ok = true, Plan = plan };
    }

    /// <summary>usage: each program's data from the service's counts (which reach the file within seconds).</summary>
    private ApiResponse Usage(ApiRequest request, DateOnly today)
    {
        var from = DataUsageStore.PeriodStart(request.Period, today);
        var period = from == today ? "today" : $"{today.DayNumber - from.DayNumber + 1}d";
        var apps = usage is null || usage.ResetRequested ? [] : DataUsageStore.Totals(usage.Load(), from);
        return new ApiResponse
        {
            Ok = true,
            Usage = new UsageInfo(period, DataUsageStore.DayText(from), apps.Sum(a => a.Sent), apps.Sum(a => a.Received), apps),
        };
    }

    /// <summary>
    /// logs: the history settings and sizes. setLogs: new settings (the service applies them within
    /// a minute, removing lines older than the new limit). clearLogs: forget every connection.
    /// </summary>
    private ApiResponse Logs(ApiRequest request)
    {
        var store = logSettings ?? throw new InvalidOperationException("History settings need the criofire service.");
        if (request.Op == ApiOps.SetLogs)
        {
            store.Save(request.LogSettings ?? throw new ArgumentException("No history settings given."));
        }
        else if (request.Op == ApiOps.ClearLogs)
        {
            foreach (var log in new[] { trafficLog, allowedLog })
            {
                if (log is not null)
                {
                    LogRetention.Clear(log);
                }
            }
        }

        DateTime? oldest = new[] { trafficLog, allowedLog }
            .Select(l => l is null ? null : LogRetention.OldestUtc(l))
            .Where(t => t is not null)
            .DefaultIfEmpty()
            .Min();
        return new ApiResponse
        {
            Ok = true,
            Logs = new LogsInfo(
                store.Load(),
                trafficLog is null ? 0 : LogRetention.Bytes(trafficLog),
                allowedLog is null ? 0 : LogRetention.Bytes(allowedLog),
                oldest),
        };
    }

    /// <summary>resetUsage: the service clears its counts within a few seconds.</summary>
    private ApiResponse ResetUsage()
    {
        (usage ?? throw new InvalidOperationException("Data counts need the criofire service.")).RequestReset();
        return new ApiResponse { Ok = true };
    }

    /// <summary>What the organization's policy does not let users change, whoever asks; null when the request may go ahead.</summary>
    private DomainRuleStore DomainStore => domainRules ?? throw new InvalidOperationException("Domain rules need the criofire service.");

    private ApiResponse Domains()
    {
        var counts = engine.IsInstalled()
            ? engine.ListDomainAddresses().GroupBy(d => d.Address.RuleId).ToDictionary(g => g.Key, g => g.Select(d => d.Address.Address).Distinct().Count())
            : [];
        return new ApiResponse
        {
            Ok = true,
            Domains = (domainRules?.List() ?? []).Select(r => DomainRuleInfo.From(r, counts.GetValueOrDefault(r.Id))).ToList(),
        };
    }

    /// <summary>Adds or replaces a domain rule. The service adds its address filters within a few seconds.</summary>
    private ApiResponse SetDomainRule(ApiRequest request)
    {
        var action = request.Action?.ToLowerInvariant() switch
        {
            "block" => RuleAction.Block,
            "allow" => RuleAction.Allow,
            _ => throw new ArgumentException("action must be block or allow."),
        };
        var app = string.IsNullOrWhiteSpace(request.App) ? null : Path.GetFullPath(request.App.Trim().Trim('"'));
        if (app is not null && !File.Exists(app))
        {
            throw new ArgumentException($"No program at {app}.");
        }

        EnsureInstalled();
        var rule = DomainStore.Set(Required(request.Domain, "domain"), action, app, ParseNetworks(request.Networks));
        return new ApiResponse { Ok = true, Domains = [DomainRuleInfo.From(rule, 0)] };
    }

    private ApiResponse RemoveDomainRule(ApiRequest request)
    {
        if (request.DomainRuleId is { Length: > 0 } id)
        {
            var rule = DomainStore.List().FirstOrDefault(r => r.Id == id) ?? throw new ArgumentException("No such domain rule.");
            if (rule.Managed)
            {
                throw new ArgumentException("This rule is set by your organization.");
            }

            DomainStore.RemoveById(id);
            return new ApiResponse { Ok = true, Count = 1 };
        }

        var removed = DomainStore.Remove(Required(request.Domain, "domain"));
        return removed == 0 ? ApiResponse.Failure($"No domain rule for {request.Domain}.") : new ApiResponse { Ok = true, Count = removed };
    }

    private static string? ManagedRefusal(ApiRequest request, ManagedPolicy managed)
    {
        if (!managed.AllowUserRules && request.Op is ApiOps.SetRule or ApiOps.RemoveRules or ApiOps.RemoveFilter or ApiOps.AddNetRule
            or ApiOps.SetServiceRule or ApiOps.RemoveServiceRules or ApiOps.ImportRules or ApiOps.RestoreBackup or ApiOps.SetAutoRule or ApiOps.Trust
            or ApiOps.SetDomainRule or ApiOps.RemoveDomainRule)
        {
            return ManagedPolicies.LockedMessage;
        }

        if (managed.Mode is not null && request.Op == ApiOps.SetMode)
        {
            return "The mode on this PC is set by your organization.";
        }

        return managed.RequireAdmin && request.Op == ApiOps.SetProtection && request.Enabled == false
            ? "Tamper protection on this PC is required by your organization."
            : null;
    }

    /// <summary>setLicense: stores a license key after checking it; an empty key goes back to free use.</summary>
    private ApiResponse SetLicense(ApiRequest request)
    {
        if (license is null)
        {
            throw new InvalidOperationException("License keys need the criofire service.");
        }

        var status = LicenseKeys.Check(request.LicenseKey, DateTime.UtcNow, _licenseKey.Value);
        if (status.State is LicenseStates.Invalid or LicenseStates.Unavailable)
        {
            return ApiResponse.Failure(status.Message);
        }

        license.Set(request.LicenseKey);
        return new ApiResponse { Ok = true, License = status };
    }

    private ApiResponse SetProtection(ApiRequest request)
    {
        if (protection is null)
        {
            throw new InvalidOperationException("Tamper protection needs the criofire service.");
        }

        protection.SetRequireAdmin(request.Enabled ?? throw new ArgumentException("enabled is required."));
        return new ApiResponse { Ok = true };
    }

    private void Backup(string reason)
    {
        if (backups is not null && engine.IsInstalled())
        {
            var current = RuleBackup.Export(engine, temporaryRules, DateTime.UtcNow, domainRules);
            if (current.Count > 0)
            {
                backups.Save(current, reason);
            }
        }
    }

    private List<AutoRuleInfo> AutoRules() =>
        engine.GetAutoRules().Select(r => new AutoRuleInfo(r.Name, r.Enabled, r.Active)).ToList();

    /// <summary>
    /// panic with action allow (everything allowed, rules paused), block (all network traffic
    /// blocked), off (rules back in force) or remove (delete every CrioFire rule; cannot be undone).
    /// </summary>
    private ApiResponse Panic(ApiRequest request)
    {
        var action = request.Action?.Trim().ToLowerInvariant();
        if (action == "remove")
        {
            Backup("before-remove-all");
            var count = engine.RemoveAllFilters();
            temporaryRules?.Clear();
            identities?.Store.Clear();
            return new ApiResponse { Ok = true, Count = count, Panic = FilterDescriptions.PanicText(PanicState.Off) };
        }

        if (!FilterDescriptions.TryParsePanic(action, out var state))
        {
            throw new ArgumentException("action must be allow (pause rules), block (block all network traffic), off (resume rules) or remove (delete every rule).");
        }

        if (state != PanicState.Off)
        {
            EnsureInstalled();
        }
        else if (!engine.IsInstalled())
        {
            return new ApiResponse { Ok = true, Count = 0, Panic = FilterDescriptions.PanicText(PanicState.Off) };
        }

        return new ApiResponse { Ok = true, Count = engine.SetPanic(state), Panic = FilterDescriptions.PanicText(state) };
    }

    private ApiResponse List()
    {
        var expiries = temporaryRules?.All() ?? [];
        var rules = engine.ListFilters().Select(f =>
        {
            var info = RuleInfo.From(f);
            var expiry = f.Kind == FilterKind.AppRule
                ? expiries.FirstOrDefault(t => string.Equals(t.App, info.App, StringComparison.OrdinalIgnoreCase))
                : null;
            return expiry is null ? info : info with { ExpiresUtc = expiry.ExpiresUtc };
        });
        return new ApiResponse { Ok = true, Rules = rules.ToList(), AutoRules = AutoRules() };
    }

    private ApiResponse RemoveRules(ApiRequest request)
    {
        var app = Required(request.App, "app");
        var count = engine.RemoveAppRules(app, ParseDirection(request.Direction, TrafficDirection.Both));
        temporaryRules?.Remove(KnownApps.Normalize(app));
        identities?.Store.Forget(KnownApps.Normalize(app));
        return new ApiResponse { Ok = true, Count = count };
    }

    private ApiResponse RemoveFilter(ApiRequest request)
    {
        var removed = engine.RemoveFilter(request.FilterId ?? throw new ArgumentException("filterId is required."));
        return new ApiResponse { Ok = true, Count = removed };
    }

    private ApiResponse AddNetRule(ApiRequest request)
    {
        var action = request.Action?.ToLowerInvariant() switch
        {
            "block" => RuleAction.Block,
            "allow" => RuleAction.Allow,
            _ => throw new ArgumentException("action must be block or allow."),
        };
        if (!NetRule.TryParseProtocol(request.Protocol, out var protocol))
        {
            throw new ArgumentException("protocol must be tcp, udp or any.");
        }

        var rule = NetRule.Create(action, ParseDirection(request.Direction, TrafficDirection.Outbound), protocol, request.Ports, request.Addresses, request.App, out var error,
            ParseNetworks(request.Networks))
            ?? throw new ArgumentException(error);
        EnsureInstalled();
        var ids = engine.AddNetRule(rule);
        return new ApiResponse { Ok = true, Count = ids.Count };
    }

    private ApiResponse SetMode(ApiRequest request)
    {
        if (!FilterDescriptions.TryParseMode(request.Mode, out var mode))
        {
            throw new ArgumentException("mode must be learning, ask or allowlist.");
        }

        EnsureInstalled();
        engine.SetMode(mode, request.Apps);
        return new ApiResponse { Ok = true, Mode = FilterDescriptions.ModeText(engine.GetMode()) };
    }

    private void EnsureInstalled()
    {
        if (!engine.IsInstalled())
        {
            engine.Install();
        }
    }

    private static string Required(string? value, string name) =>
        string.IsNullOrWhiteSpace(value) ? throw new ArgumentException($"{name} is required.") : value;

    private static NetworkProfiles ParseNetworks(string? text) =>
        NetworkScope.TryParse(text, out var networks) ? networks : throw new ArgumentException("networks must be any, or a list of domain, private and public.");

    private static TrafficDirection ParseDirection(string? text, TrafficDirection fallback) => text?.ToLowerInvariant() switch
    {
        null or "" => fallback,
        "out" => TrafficDirection.Outbound,
        "in" => TrafficDirection.Inbound,
        "both" => TrafficDirection.Both,
        _ => throw new ArgumentException("direction must be out, in or both."),
    };
}
