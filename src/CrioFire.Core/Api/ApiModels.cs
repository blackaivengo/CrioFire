using System.Text.Json;
using System.Text.Json.Serialization;

namespace CrioFire.Core.Api;

/// <summary>
/// The local API between criofire-svc and its clients (criofire-ui.exe, criofire.exe), carried
/// over the named pipe \\.\pipe\criofire as one JSON object per line in each direction.
/// </summary>
public static class ApiOps
{
    public const string Status = "status";
    public const string List = "list";
    public const string Events = "events";
    public const string SetRule = "setRule";
    public const string RemoveRules = "removeRules";
    public const string RemoveFilter = "removeFilter";
    public const string SetMode = "setMode";
    public const string Panic = "panic";

    /// <summary>Operations that change the firewall and need an authorized client.</summary>
    public static bool IsWrite(string op) => op is SetRule or RemoveRules or RemoveFilter or SetMode or Panic;
}

public sealed record ApiRequest
{
    public string Op { get; init; } = string.Empty;

    /// <summary>setRule, removeRules: program path.</summary>
    public string? App { get; init; }

    /// <summary>setRule: block or allow.</summary>
    public string? Action { get; init; }

    /// <summary>setRule, removeRules: out, in or both.</summary>
    public string? Direction { get; init; }

    /// <summary>setMode: learning, ask or allowlist.</summary>
    public string? Mode { get; init; }

    /// <summary>setMode: programs to allow at the same time.</summary>
    public List<string>? Apps { get; init; }

    /// <summary>events: how far back.</summary>
    public int? Minutes { get; init; }

    /// <summary>events: include drops by other firewalls.</summary>
    public bool? All { get; init; }

    /// <summary>removeFilter: the filter ID.</summary>
    public ulong? FilterId { get; init; }
}

public sealed record ApiResponse
{
    public bool Ok { get; init; }

    public string? Error { get; init; }

    public StatusInfo? Status { get; init; }

    public List<RuleInfo>? Rules { get; init; }

    public List<EventInfo>? Events { get; init; }

    /// <summary>Filters added or removed by a write operation.</summary>
    public int? Count { get; init; }

    /// <summary>The mode after setMode.</summary>
    public string? Mode { get; init; }

    public static ApiResponse Failure(string error) => new() { Ok = false, Error = error };
}

public sealed record StatusInfo(bool Installed, string Mode, int FilterCount, string Version);

public sealed record RuleInfo(ulong FilterId, string Kind, string? Action, string? Direction, string? App, string? Layer, string Name)
{
    public static RuleInfo From(CrioFireFilter f) => new(
        f.FilterId,
        f.Kind.ToString(),
        f.Rule is null ? (f.Kind == FilterKind.DefaultBlock ? "block" : f.Kind == FilterKind.BuiltInAllow ? "allow" : null) : RuleDescription.ActionText(f.Rule.Action),
        f.Rule is null ? null : RuleDescription.DirectionText(f.Rule.Direction),
        f.Rule?.AppPath,
        f.Layer?.Name,
        f.Name);
}

public sealed record EventInfo(DateTime TimeUtc, string? App, string Protocol, string? Local, string? Remote, string? Direction, bool CrioFire, ulong FilterId)
{
    public static EventInfo From(BlockedConnection e) => new(
        e.TimeUtc,
        e.AppPath,
        e.ProtocolName,
        e.Local?.ToString(),
        e.Remote?.ToString(),
        e.Direction switch { TrafficDirection.Outbound => "out", TrafficDirection.Inbound => "in", _ => null },
        e.IsCrioFire,
        e.FilterId);
}

/// <summary>One-line JSON encoding for the pipe protocol (source-generated, no reflection).</summary>
public static class ApiJson
{
    public static string Serialize(ApiRequest request) => JsonSerializer.Serialize(request, ApiJsonContext.Default.ApiRequest);

    public static string Serialize(ApiResponse response) => JsonSerializer.Serialize(response, ApiJsonContext.Default.ApiResponse);

    public static ApiRequest? DeserializeRequest(string line) => JsonSerializer.Deserialize(line, ApiJsonContext.Default.ApiRequest);

    public static ApiResponse? DeserializeResponse(string line) => JsonSerializer.Deserialize(line, ApiJsonContext.Default.ApiResponse);
}

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase, DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
[JsonSerializable(typeof(ApiRequest))]
[JsonSerializable(typeof(ApiResponse))]
internal sealed partial class ApiJsonContext : JsonSerializerContext
{
}
