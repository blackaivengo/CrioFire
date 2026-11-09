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

/// <summary>What a rule does with matching traffic.</summary>
public enum RuleAction
{
    Block,
    Allow,
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
/// Format: <c>criofire:v1|block|out|C:\Path\app.exe</c>.
/// </summary>
public sealed record RuleDescription(RuleAction Action, TrafficDirection Direction, string AppPath)
{
    public const string Prefix = "criofire:v1";

    public string Format() =>
        string.Join('|', Prefix, ActionText(Action), DirectionText(Direction), AppPath);

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

        RuleAction? action = parts[1] switch { "block" => RuleAction.Block, "allow" => RuleAction.Allow, _ => null };
        TrafficDirection? direction = parts[2] switch
        {
            "out" => TrafficDirection.Outbound,
            "in" => TrafficDirection.Inbound,
            "both" => TrafficDirection.Both,
            _ => null,
        };

        if (action is null || direction is null)
        {
            return false;
        }

        rule = new RuleDescription(action.Value, direction.Value, parts[3]);
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
    RuleDescription? Rule);
