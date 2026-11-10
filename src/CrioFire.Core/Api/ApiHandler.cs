using System.Reflection;

namespace CrioFire.Core.Api;

/// <summary>
/// Carries out API requests against the filtering engine. Used by the service for pipe clients,
/// and directly by criofire.exe when it runs elevated (so both paths behave identically).
/// Thread-safe: requests are handled one at a time.
/// </summary>
public sealed class ApiHandler(WfpEngine engine, TemporaryRuleStore? temporaryRules = null, TrafficLog? trafficLog = null)
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

        if (request.Op == ApiOps.Report)
        {
            // Reads only the log file, not the engine: no need to hold up other clients.
            try
            {
                return Report(request);
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
                    ApiOps.Panic => Panic(),
                    ApiOps.AddNetRule => AddNetRule(request),
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
                Version),
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
        var app = Path.GetFullPath(Required(request.App, "app"));
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
        var events = TrafficHistory.Read(trafficLog, from - (to - from));   // the period before, for the comparison
        return new ApiResponse { Ok = true, Report = ReportBuilder.Build(events, period, now) };
    }

    private ApiResponse Panic()
    {
        var count = engine.RemoveAllFilters();
        temporaryRules?.Clear();
        return new ApiResponse { Ok = true, Count = count };
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
        return new ApiResponse { Ok = true, Rules = rules.ToList() };
    }

    private ApiResponse RemoveRules(ApiRequest request)
    {
        var app = Required(request.App, "app");
        var count = engine.RemoveAppRules(app, ParseDirection(request.Direction, TrafficDirection.Both));
        temporaryRules?.Remove(Path.GetFullPath(app));
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
