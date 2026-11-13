using System.Reflection;

namespace CrioFire.Core.Api;

/// <summary>
/// Carries out API requests against the filtering engine. Used by the service for pipe clients,
/// and directly by criofire.exe when it runs elevated (so both paths behave identically).
/// Thread-safe: requests are handled one at a time.
/// </summary>
/// <param name="allowedLog">The service's log of allowed connections (allowed.log), for reports and the allowed list.</param>
/// <param name="identities">Checks that allowed programs stay the files the user allowed; null where not used (tests).</param>
public sealed class ApiHandler(WfpEngine engine, TemporaryRuleStore? temporaryRules = null, TrafficLog? trafficLog = null, TrafficLog? allowedLog = null, IdentityGuard? identities = null)
{
    private static readonly string Version =
        typeof(ApiHandler).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? "unknown";

    private readonly Lock _gate = new();

    public ApiResponse Handle(ApiRequest request, bool canWrite)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (ApiOps.IsWrite(request.Op) && !canWrite)
        {
            return ApiResponse.Failure("Not allowed: changing rules needs an administrator, or CrioFire's own app or command line.");
        }

        if (request.Op is ApiOps.Report or ApiOps.Allowed or ApiOps.Traffic)
        {
            // Reads only the log files, not the engine: no need to hold up other clients.
            try
            {
                return request.Op switch
                {
                    ApiOps.Report => Report(request),
                    ApiOps.Allowed => Allowed(request),
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
                identities?.Store.Changed().Count ?? 0),
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
        var ids = engine.SetAppRule(app, action, direction);
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
        var ids = engine.SetServiceRule(service, action, ParseDirection(request.Direction, TrafficDirection.Outbound));
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
        var ids = engine.SetAppRule(app, RuleAction.Allow, direction);
        identities.Record(app, DateTime.UtcNow);
        return new ApiResponse { Ok = true, Count = ids.Count };
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

        var rule = NetRule.Create(action, ParseDirection(request.Direction, TrafficDirection.Outbound), protocol, request.Ports, request.Addresses, request.App, out var error)
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

    private static TrafficDirection ParseDirection(string? text, TrafficDirection fallback) => text?.ToLowerInvariant() switch
    {
        null or "" => fallback,
        "out" => TrafficDirection.Outbound,
        "in" => TrafficDirection.Inbound,
        "both" => TrafficDirection.Both,
        _ => throw new ArgumentException("direction must be out, in or both."),
    };
}
