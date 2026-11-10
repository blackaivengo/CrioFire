using System.Reflection;

namespace CrioFire.Core.Api;

/// <summary>
/// Carries out API requests against the filtering engine. Used by the service for pipe clients,
/// and directly by criofire.exe when it runs elevated (so both paths behave identically).
/// Thread-safe: requests are handled one at a time.
/// </summary>
public sealed class ApiHandler(WfpEngine engine)
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

        lock (_gate)
        {
            try
            {
                return request.Op switch
                {
                    ApiOps.Status => Status(),
                    ApiOps.List => new ApiResponse { Ok = true, Rules = engine.ListFilters().Select(RuleInfo.From).ToList() },
                    ApiOps.Events => Events(request),
                    ApiOps.SetRule => SetRule(request),
                    ApiOps.RemoveRules => new ApiResponse { Ok = true, Count = engine.RemoveAppRules(Required(request.App, "app"), ParseDirection(request.Direction, TrafficDirection.Both)) },
                    ApiOps.RemoveFilter => RemoveFilter(request),
                    ApiOps.SetMode => SetMode(request),
                    ApiOps.Panic => new ApiResponse { Ok = true, Count = engine.RemoveAllFilters() },
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
        EnsureInstalled();
        var ids = engine.SetAppRule(Required(request.App, "app"), action, ParseDirection(request.Direction, TrafficDirection.Outbound));
        return new ApiResponse { Ok = true, Count = ids.Count };
    }

    private ApiResponse RemoveFilter(ApiRequest request)
    {
        engine.RemoveFilter(request.FilterId ?? throw new ArgumentException("filterId is required."));
        return new ApiResponse { Ok = true, Count = 1 };
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
