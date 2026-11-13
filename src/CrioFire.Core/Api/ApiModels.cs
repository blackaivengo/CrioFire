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
    public const string Report = "report";
    public const string AddNetRule = "addNetRule";
    public const string Allowed = "allowed";
    public const string Traffic = "traffic";
    public const string SetServiceRule = "setServiceRule";
    public const string RemoveServiceRules = "removeServiceRules";
    public const string SetAutoRule = "setAutoRule";
    public const string Changed = "changed";
    public const string Trust = "trust";
    public const string ExportRules = "exportRules";
    public const string ImportRules = "importRules";
    public const string Backups = "backups";
    public const string RestoreBackup = "restoreBackup";
    public const string SetProtection = "setProtection";
    public const string License = "license";
    public const string SetLicense = "setLicense";

    /// <summary>Operations that change the firewall and need an authorized client.</summary>
    public static bool IsWrite(string op) =>
        op is SetRule or RemoveRules or RemoveFilter or SetMode or Panic or AddNetRule or SetServiceRule or RemoveServiceRules or SetAutoRule or Trust or ImportRules or RestoreBackup or SetProtection or SetLicense;

    /// <summary>The error code when a change needs administrator approval (tamper protection, or the setting itself).</summary>
    public const string ApprovalRequired = "approval-required";
}

public sealed record ApiRequest
{
    public string Op { get; init; } = string.Empty;

    /// <summary>setRule, removeRules: program path.</summary>
    public string? App { get; init; }

    /// <summary>setRule, setServiceRule: block or allow. panic: allow, block, off or remove.</summary>
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

    /// <summary>setRule: make the rule temporary; CrioFire removes it after this many minutes.</summary>
    public int? ExpiresMinutes { get; init; }

    /// <summary>report: 24h, 7d or 30d.</summary>
    public string? Period { get; init; }

    /// <summary>addNetRule: tcp, udp or any.</summary>
    public string? Protocol { get; init; }

    /// <summary>addNetRule: ports and ranges, e.g. "80,443,8000-8100" (remote port outbound, local port inbound).</summary>
    public string? Ports { get; init; }

    /// <summary>addNetRule: remote addresses, CIDR blocks or ranges, e.g. "10.0.0.0/8,203.0.113.5".</summary>
    public string? Addresses { get; init; }

    /// <summary>setServiceRule, removeServiceRules: the service's key name, e.g. "Dnscache".</summary>
    public string? Service { get; init; }

    /// <summary>importRules: the rules to import.</summary>
    public RuleSet? RuleSet { get; init; }

    /// <summary>importRules: merge (default) or replace.</summary>
    public string? ImportMode { get; init; }

    /// <summary>importRules, restoreBackup: only report what would change.</summary>
    public bool? DryRun { get; init; }

    /// <summary>importRules: also switch to the mode in the file.</summary>
    public bool? WithMode { get; init; }

    /// <summary>setLicense: the license key; empty removes it.</summary>
    public string? LicenseKey { get; init; }

    /// <summary>restoreBackup: a backup name from the backups operation.</summary>
    public string? Name { get; init; }

    /// <summary>setAutoRule: svchost or system.</summary>
    public string? AutoRule { get; init; }

    /// <summary>setAutoRule: switch it on or off.</summary>
    public bool? Enabled { get; init; }

    /// <summary>allowed, traffic: include traffic that stays on this PC (loopback). Default false.</summary>
    public bool? IncludeLoopback { get; init; }

    /// <summary>traffic: blocked, allowed or all.</summary>
    public string? TrafficKind { get; init; }

    /// <summary>traffic: words that must all appear (program, service, address, port, reason).</summary>
    public string? Search { get; init; }

    /// <summary>traffic: a reason group (mine, norule, automatic, loopback, panic).</summary>
    public string? Why { get; init; }

    /// <summary>traffic: recent (default) or count.</summary>
    public string? Sort { get; init; }

    /// <summary>traffic: paging.</summary>
    public int? Offset { get; init; }

    public int? Limit { get; init; }
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

    public ReportInfo? Report { get; init; }

    /// <summary>panic: the panic switch afterwards (off, allow, block).</summary>
    public string? Panic { get; init; }

    /// <summary>traffic: one page of grouped blocked and/or allowed connections.</summary>
    public TrafficPage? Traffic { get; init; }

    /// <summary>allowed: connections allowed in the window, grouped.</summary>
    public List<AllowedGroup>? Allowed { get; init; }

    /// <summary>list: CrioFire's automatic permits and whether they are on.</summary>
    public List<AutoRuleInfo>? AutoRules { get; init; }

    /// <summary>exportRules: every rule in force.</summary>
    public RuleSet? RuleSet { get; init; }

    /// <summary>importRules, restoreBackup: what was (or, with dryRun, would be) done.</summary>
    public ImportPlan? Plan { get; init; }

    /// <summary>license, setLicense: the license on this PC.</summary>
    public LicenseStatus? License { get; init; }

    /// <summary>backups: the saved rule backups, newest first.</summary>
    public List<BackupInfo>? Backups { get; init; }

    /// <summary>changed: programs whose file changed since they were allowed.</summary>
    public List<ChangedProgram>? Changed { get; init; }

    /// <summary>A machine-readable reason for a failure, e.g. <see cref="ApiOps.ApprovalRequired"/>.</summary>
    public string? Code { get; init; }

    public static ApiResponse Failure(string error, string? code = null) => new() { Ok = false, Error = error, Code = code };
}

/// <param name="Panic">The panic switch: off, allow (everything allowed, rules paused) or block (all network traffic blocked).</param>
/// <param name="ChangedPrograms">How many allowed programs changed since they were allowed (see the changed operation).</param>
/// <param name="RequireAdmin">Tamper protection: changes need administrator approval.</param>
public sealed record StatusInfo(bool Installed, string Mode, int FilterCount, string Version, string Panic = "off", int ChangedPrograms = 0, bool RequireAdmin = false);

/// <param name="Name">svchost or system.</param>
/// <param name="Enabled">Switched on (the saved choice).</param>
/// <param name="Active">In force right now (on, and the mode is Ask or Allow-list).</param>
public sealed record AutoRuleInfo(string Name, bool Enabled, bool Active);

/// <param name="Protocol">Network rules: tcp, udp or any.</param>
/// <param name="Ports">Network rules: ports and ranges, or null for any.</param>
/// <param name="Addresses">Network rules: remote addresses, or null for any.</param>
/// <param name="Summary">Network rules: a short description such as "TCP · port 445".</param>
public sealed record RuleInfo(
    ulong FilterId,
    string Kind,
    string? Action,
    string? Direction,
    string? App,
    string? Layer,
    string Name,
    DateTime? ExpiresUtc = null,
    string? Protocol = null,
    string? Ports = null,
    string? Addresses = null,
    string? Summary = null,
    string? Service = null)
{
    public static RuleInfo From(CrioFireFilter f)
    {
        if (f.Service is { } s)
        {
            return new RuleInfo(
                f.FilterId, f.Kind.ToString(), RuleDescription.ActionText(s.Action), RuleDescription.DirectionText(s.Direction), null, f.Layer?.Name, f.Name,
                Service: s.ServiceName);
        }

        if (f.Net is { } n)
        {
            return new RuleInfo(
                f.FilterId, f.Kind.ToString(), RuleDescription.ActionText(n.Action), RuleDescription.DirectionText(n.Direction), n.AppPath, f.Layer?.Name, f.Name,
                Protocol: NetRule.ProtocolText(n.Protocol),
                Ports: n.Ports.Length == 0 ? null : n.Ports,
                Addresses: n.Addresses.Length == 0 ? null : n.Addresses,
                Summary: n.Summary());
        }

        return new RuleInfo(
            f.FilterId,
            f.Kind.ToString(),
            f.Rule is null ? (f.Kind == FilterKind.DefaultBlock ? "block" : f.Kind == FilterKind.BuiltInAllow ? "allow" : null) : RuleDescription.ActionText(f.Rule.Action),
            f.Rule is null ? null : RuleDescription.DirectionText(f.Rule.Direction),
            f.Rule?.AppPath ?? (f.Kind == FilterKind.BuiltInAllow
                ? (string.Equals(f.BuiltIn, AutoRulePolicy.WindowsKernel, StringComparison.OrdinalIgnoreCase) ? KnownApps.Kernel : "svchost.exe")
                : null),
            f.Layer?.Name,
            f.Name);
    }
}

/// <param name="Kind">The kind of CrioFire filter that blocked it (e.g. DefaultBlock in Ask mode), or null for other firewalls.</param>
public sealed record EventInfo(DateTime TimeUtc, string? App, string Protocol, string? Local, string? Remote, string? Direction, bool CrioFire, ulong FilterId, string? Kind = null)
{
    public static EventInfo From(BlockedConnection e) => new(
        e.TimeUtc,
        e.AppPath,
        e.ProtocolName,
        e.Local?.ToString(),
        e.Remote?.ToString(),
        e.Direction switch { TrafficDirection.Outbound => "out", TrafficDirection.Inbound => "in", _ => null },
        e.IsCrioFire,
        e.FilterId,
        e.Rule?.Kind.ToString());
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
