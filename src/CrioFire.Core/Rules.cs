namespace CrioFire.Core;

/// <summary>Which traffic a rule covers.</summary>
[Flags]
public enum TrafficDirection
{
    /// <summary>Connections this PC starts (an app sending).</summary>
    Outbound = 1,

    /// <summary>Connections other machines start (an app listening and receiving).</summary>
    Inbound = 2,

    /// <summary>Both directions.</summary>
    Both = Outbound | Inbound,
}

/// <summary>What CrioFire does with outbound connections from programs that have no rule.</summary>
public enum FirewallMode
{
    /// <summary>Allow them (nothing is blocked unless a rule says so).</summary>
    Learning,

    /// <summary>Block them; the app will ask the user (alerts arrive in a later step).</summary>
    Ask,

    /// <summary>Block them silently: only programs with an allow rule may connect.</summary>
    AllowList,
}

/// <summary>What a CrioFire filter is for.</summary>
public enum FilterKind
{
    /// <summary>A user rule for one program (block or allow).</summary>
    AppRule,

    /// <summary>The catch-all block that Ask and Allow-list modes add (outbound, loopback exempt).</summary>
    DefaultBlock,

    /// <summary>A permit CrioFire adds in Ask/Allow-list modes so Windows keeps working (Windows services, kernel).</summary>
    BuiltInAllow,

    /// <summary>A CrioFire filter whose description this version does not understand.</summary>
    Unknown,

    /// <summary>A user rule by port and/or remote address, optionally for one program.</summary>
    NetRule,

    /// <summary>A user rule for one Windows service (matched by its service SID).</summary>
    ServiceRule,

    /// <summary>The panic switch: allow everything (rules paused) or block all network traffic, above every rule.</summary>
    Panic,
}

/// <summary>
/// The panic switch. Both states sit above every rule without touching them, so switching panic off
/// brings back exactly the rules and mode there were before.
/// </summary>
public enum PanicState
{
    /// <summary>Rules and mode apply as usual.</summary>
    Off,

    /// <summary>Every connection is allowed; CrioFire's rules and mode are kept but paused.</summary>
    AllowAll,

    /// <summary>Every network connection, in and out, is blocked. Traffic that stays on this PC still works.</summary>
    BlockAll,
}

/// <summary>Descriptions for CrioFire's non-rule filters, e.g. <c>criofire:v1|default|ask</c>.</summary>
public static class FilterDescriptions
{
    public static string DefaultBlock(FirewallMode mode) => $"{RuleDescription.Prefix}|default|{ModeText(mode)}";

    public static string BuiltInAllow(string name) => $"{RuleDescription.Prefix}|builtin|{name}";

    public static string Panic(PanicState state) => $"{RuleDescription.Prefix}|panic|{PanicText(state)}";

    public static string PanicText(PanicState state) => state switch
    {
        PanicState.AllowAll => "allow",
        PanicState.BlockAll => "block",
        _ => "off",
    };

    public static bool TryParsePanic(string? text, out PanicState state)
    {
        switch (text?.Trim().ToLowerInvariant())
        {
            case "allow" or "allowall" or "allow-all":
                state = PanicState.AllowAll;
                return true;
            case "block" or "blockall" or "block-all":
                state = PanicState.BlockAll;
                return true;
            case "off" or "resume":
                state = PanicState.Off;
                return true;
            default:
                state = PanicState.Off;
                return false;
        }
    }

    /// <summary>The state in a panic filter's description, or null.</summary>
    public static PanicState? PanicOf(string? description)
    {
        var parts = description?.Split('|') ?? [];
        return parts.Length == 3 && parts[0] == RuleDescription.Prefix && parts[1] == "panic"
            && TryParsePanic(parts[2], out var state) && state != PanicState.Off ? state : null;
    }

    public static (FilterKind Kind, FirewallMode? Mode) Classify(string? description)
    {
        if (RuleDescription.TryParse(description, out _))
        {
            return (FilterKind.AppRule, null);
        }

        if (NetRule.TryParse(description, out _))
        {
            return (FilterKind.NetRule, null);
        }

        if (ServiceRule.TryParse(description, out _))
        {
            return (FilterKind.ServiceRule, null);
        }

        var parts = description?.Split('|') ?? [];
        if (parts.Length == 3 && parts[0] == RuleDescription.Prefix)
        {
            if (parts[1] == "default" && TryParseMode(parts[2], out var mode) && mode != FirewallMode.Learning)
            {
                return (FilterKind.DefaultBlock, mode);
            }

            if (parts[1] == "builtin" && parts[2].Length > 0)
            {
                return (FilterKind.BuiltInAllow, null);
            }

            if (PanicOf(description) is not null)
            {
                return (FilterKind.Panic, null);
            }
        }

        return (FilterKind.Unknown, null);
    }

    /// <summary>The name in a built-in permit's description (svchost, system), or null.</summary>
    public static string? BuiltInName(string? description)
    {
        var parts = description?.Split('|') ?? [];
        return parts.Length == 3 && parts[0] == RuleDescription.Prefix && parts[1] == "builtin" && parts[2].Length > 0 ? parts[2] : null;
    }

    public static string ModeText(FirewallMode mode) => mode switch
    {
        FirewallMode.Learning => "learning",
        FirewallMode.Ask => "ask",
        FirewallMode.AllowList => "allowlist",
        _ => throw new ArgumentOutOfRangeException(nameof(mode)),
    };

    public static bool TryParseMode(string? text, out FirewallMode mode)
    {
        switch (text?.Trim().ToLowerInvariant())
        {
            case "learning":
                mode = FirewallMode.Learning;
                return true;
            case "ask":
                mode = FirewallMode.Ask;
                return true;
            case "allowlist" or "allow-list":
                mode = FirewallMode.AllowList;
                return true;
            default:
                mode = default;
                return false;
        }
    }
}

/// <summary>What a rule does with matching traffic.</summary>
public enum RuleAction
{
    Block,
    Allow,
}

/// <summary>
/// The kinds of network a rule applies on, as Windows sorts the networks a PC joins (the same
/// categories as Windows Firewall's profiles). None set means every network.
/// </summary>
[Flags]
public enum NetworkProfiles
{
    /// <summary>Every network (the rule has no network condition).</summary>
    Any = 0,

    /// <summary>A network where Windows reaches the organization's domain controller (a work network).</summary>
    Domain = 1,

    /// <summary>A network the user marked as private: home, or a trusted office.</summary>
    Private = 2,

    /// <summary>Every other network: cafés, hotels, airports, and networks Windows does not know.</summary>
    Public = 4,
}

/// <summary>Text, parsing and labels for <see cref="NetworkProfiles"/>.</summary>
public static class NetworkScope
{
    public const NetworkProfiles All = NetworkProfiles.Domain | NetworkProfiles.Private | NetworkProfiles.Public;

    private static readonly (NetworkProfiles Profile, string Text, uint Id)[] Known =
    [
        (NetworkProfiles.Domain, "domain", 3),
        (NetworkProfiles.Private, "private", 2),
        (NetworkProfiles.Public, "public", 1),
    ];

    /// <summary>All three is the same as every network.</summary>
    public static NetworkProfiles Normalize(NetworkProfiles profiles) =>
        (profiles & All) == All ? NetworkProfiles.Any : profiles & All;

    /// <summary>"domain,private", or "any" for every network.</summary>
    public static string Text(NetworkProfiles profiles)
    {
        var p = Normalize(profiles);
        return p == NetworkProfiles.Any ? "any" : string.Join(',', Known.Where(k => p.HasFlag(k.Profile)).Select(k => k.Text));
    }

    /// <summary>The text for files and the API: null for every network, so such rules look as they always did.</summary>
    public static string? TextOrNull(NetworkProfiles profiles) => Normalize(profiles) == NetworkProfiles.Any ? null : Text(profiles);

    /// <summary>Parses "public", "domain,private", "home" (= private), "work" (= domain); empty, null or "any" is every network.</summary>
    public static bool TryParse(string? text, out NetworkProfiles profiles)
    {
        profiles = NetworkProfiles.Any;
        if (string.IsNullOrWhiteSpace(text) || text.Trim().Equals("any", StringComparison.OrdinalIgnoreCase) || text.Trim() == "*")
        {
            return true;
        }

        foreach (var part in text.Split([',', '+', ' '], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            switch (part.ToLowerInvariant())
            {
                case "domain" or "work": profiles |= NetworkProfiles.Domain; break;
                case "private" or "home": profiles |= NetworkProfiles.Private; break;
                case "public": profiles |= NetworkProfiles.Public; break;
                default:
                    profiles = NetworkProfiles.Any;
                    return false;
            }
        }

        profiles = Normalize(profiles);
        return true;
    }

    /// <summary>For people: "public networks", "private and domain networks", or "every network".</summary>
    public static string Label(NetworkProfiles profiles)
    {
        var p = Normalize(profiles);
        if (p == NetworkProfiles.Any)
        {
            return "every network";
        }

        var names = Known.Where(k => p.HasFlag(k.Profile)).Select(k => k.Text).Reverse().ToList();
        return (names.Count == 1 ? names[0] : string.Join(", ", names.Take(names.Count - 1)) + " and " + names[^1]) + " networks";
    }

    /// <summary>The values of the WFP condition FWPM_CONDITION_CURRENT_PROFILE_ID: public 1, private 2, domain 3.</summary>
    public static IReadOnlyList<uint> ProfileIds(NetworkProfiles profiles)
    {
        var p = Normalize(profiles);
        return Known.Where(k => p.HasFlag(k.Profile)).Select(k => k.Id).ToList();
    }

    /// <summary>The action field of a rule description: "block", or "block@public" for a rule on some networks only.</summary>
    public static string ActionField(RuleAction action, NetworkProfiles profiles) =>
        Normalize(profiles) == NetworkProfiles.Any ? RuleDescription.ActionText(action) : $"{RuleDescription.ActionText(action)}@{Text(profiles)}";

    public static bool TryParseActionField(string? field, out RuleAction action, out NetworkProfiles profiles)
    {
        action = RuleAction.Block;
        profiles = NetworkProfiles.Any;
        if (field is null)
        {
            return false;
        }

        var at = field.IndexOf('@', StringComparison.Ordinal);
        var actionText = at < 0 ? field : field[..at];
        RuleAction? parsed = actionText switch { "block" => RuleAction.Block, "allow" => RuleAction.Allow, _ => null };
        if (parsed is null || (at >= 0 && (!TryParse(field[(at + 1)..], out profiles) || profiles == NetworkProfiles.Any)))
        {
            return false;
        }

        action = parsed.Value;
        return true;
    }
}

/// <summary>A WFP layer CrioFire writes filters into.</summary>
public sealed record FilterLayer(Guid Key, string Name, TrafficDirection Direction);

/// <summary>Picks the WFP layers for a direction: one IPv4 and one IPv6 layer per direction.</summary>
public static class FilterLayers
{
    public static readonly FilterLayer ConnectV4 = new(WfpIds.LayerAleAuthConnectV4, "outbound IPv4", TrafficDirection.Outbound);
    public static readonly FilterLayer ConnectV6 = new(WfpIds.LayerAleAuthConnectV6, "outbound IPv6", TrafficDirection.Outbound);
    public static readonly FilterLayer RecvAcceptV4 = new(WfpIds.LayerAleAuthRecvAcceptV4, "inbound IPv4", TrafficDirection.Inbound);
    public static readonly FilterLayer RecvAcceptV6 = new(WfpIds.LayerAleAuthRecvAcceptV6, "inbound IPv6", TrafficDirection.Inbound);

    public static IReadOnlyList<FilterLayer> All { get; } = [ConnectV4, ConnectV6, RecvAcceptV4, RecvAcceptV6];

    public static IReadOnlyList<FilterLayer> For(TrafficDirection direction)
    {
        if (direction == 0 || (direction & ~TrafficDirection.Both) != 0)
        {
            throw new ArgumentOutOfRangeException(nameof(direction), direction, "Direction must be Outbound, Inbound or Both.");
        }

        return All.Where(l => direction.HasFlag(l.Direction)).ToArray();
    }

    public static FilterLayer? Find(Guid key) => All.FirstOrDefault(l => l.Key == key);
}

/// <summary>
/// The rule CrioFire stores in a filter's description, so rules can be listed back
/// from the Base Filtering Engine without a separate database.
/// Format: <c>criofire:v1|block|out|C:\Path\app.exe</c>; a rule for some networks only has them
/// after the action: <c>criofire:v1|block@public|out|...</c>.
/// </summary>
public sealed record RuleDescription(RuleAction Action, TrafficDirection Direction, string AppPath, NetworkProfiles Networks = NetworkProfiles.Any)
{
    public const string Prefix = "criofire:v1";

    public string Format() =>
        string.Join('|', Prefix, NetworkScope.ActionField(Action, Networks), DirectionText(Direction), AppPath);

    public static bool TryParse(string? text, out RuleDescription? rule)
    {
        rule = null;
        if (string.IsNullOrEmpty(text))
        {
            return false;
        }

        // The path is last and may itself contain '|' in theory, so split into at most 4 parts.
        var parts = text.Split('|', 4);
        if (parts.Length != 4 || parts[0] != Prefix || parts[3].Length == 0)
        {
            return false;
        }

        TrafficDirection? direction = parts[2] switch
        {
            "out" => TrafficDirection.Outbound,
            "in" => TrafficDirection.Inbound,
            "both" => TrafficDirection.Both,
            _ => null,
        };

        if (!NetworkScope.TryParseActionField(parts[1], out var action, out var networks) || direction is null)
        {
            return false;
        }

        rule = new RuleDescription(action, direction.Value, parts[3], networks);
        return true;
    }

    public static string ActionText(RuleAction action) => action switch
    {
        RuleAction.Block => "block",
        RuleAction.Allow => "allow",
        _ => throw new ArgumentOutOfRangeException(nameof(action)),
    };

    public static string DirectionText(TrafficDirection direction) => direction switch
    {
        TrafficDirection.Outbound => "out",
        TrafficDirection.Inbound => "in",
        TrafficDirection.Both => "both",
        _ => throw new ArgumentOutOfRangeException(nameof(direction)),
    };
}

/// <summary>One CrioFire filter as read back from the Base Filtering Engine.</summary>
public sealed record CrioFireFilter(
    ulong FilterId,
    string Name,
    FilterLayer? Layer,
    RuleDescription? Rule,
    FilterKind Kind = FilterKind.AppRule,
    FirewallMode? Mode = null,
    NetRule? Net = null,
    string? BuiltIn = null,
    ServiceRule? Service = null,
    PanicState? Panic = null,
    bool Managed = false);
