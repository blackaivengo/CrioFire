using System.Globalization;
using System.Net;
using CrioFire.Core.Api;

namespace CrioFire.Core;

/// <summary>A port or address that a block rule covers, for the Rules page's "what is blocked" summary.</summary>
/// <param name="Kind">port or address.</param>
/// <param name="Value">What to search for: "445", "8000-8100", "203.0.113.0/24".</param>
/// <param name="Label">"445 · SMB (file sharing) · inbound · any program".</param>
public sealed record BlockedTarget(string Kind, string Value, string Label);

/// <summary>Filtering, summarizing and changing rules for the Rules page. Pure logic, unit-tested.</summary>
public static class RuleViews
{
    /// <summary>
    /// Does the rule match? <paramref name="action"/>: allow, block or null; <paramref name="direction"/>:
    /// out, in or null (a "both" rule matches either); every search word must match the program,
    /// service, rule text, ports (a number matches a range containing it) or addresses (an IP
    /// matches a block or range containing it).
    /// </summary>
    public static bool Matches(RuleInfo rule, string? search, string? action = null, string? direction = null)
    {
        ArgumentNullException.ThrowIfNull(rule);
        if (action is "allow" or "block" && rule.Action != action)
        {
            return false;
        }

        if (direction is "out" or "in" && rule.Direction != direction && rule.Direction != "both")
        {
            return false;
        }

        foreach (var word in (search ?? string.Empty).Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (!MatchesWord(rule, word))
            {
                return false;
            }
        }

        return true;
    }

    private static bool MatchesWord(RuleInfo r, string word)
    {
        static bool Has(string? text, string w) => text is not null && text.Contains(w, StringComparison.OrdinalIgnoreCase);

        if (Has(r.App, word) || Has(KnownApps.DisplayName(r.App), word) || Has(r.Service, word) || Has(r.Summary, word)
            || Has(r.Ports, word) || Has(r.Addresses, word) || Has(r.Protocol, word) || Has(r.Name, word))
        {
            return true;
        }

        var port = word.TrimStart(':');
        if (ushort.TryParse(port, NumberStyles.None, CultureInfo.InvariantCulture, out var number)
            && PortRange.TryParseList(r.Ports, out var ports, out _)
            && ports.Any(p => number >= p.Low && number <= p.High))
        {
            return true;
        }

        return IPAddress.TryParse(word, out var ip)
            && AddressRange.TryParseList(r.Addresses, out var ranges, out _)
            && ranges.Any(a => a.Contains(ip));
    }

    /// <summary>The ports and addresses that block rules cover, one entry per port range or address block.</summary>
    public static IReadOnlyList<BlockedTarget> Blocked(IEnumerable<RuleInfo> rules)
    {
        ArgumentNullException.ThrowIfNull(rules);
        var result = new List<BlockedTarget>();
        foreach (var r in rules.Where(r => r.Kind == nameof(FilterKind.NetRule) && r.Action == "block"))
        {
            var who = r.App is null ? "any program" : KnownApps.DisplayName(r.App);
            var direction = r.Direction switch { "in" => "inbound", "both" => "in and out", _ => "outbound" };
            var protocol = r.Protocol is null or "any" ? string.Empty : $"{r.Protocol.ToUpperInvariant()} ";
            if (PortRange.TryParseList(r.Ports, out var ports, out _))
            {
                foreach (var p in ports)
                {
                    var text = p.ToString();
                    var name = p.Low == p.High && NetworkFacts.PortName(p.Low) is { } known ? $" · {known}" : string.Empty;
                    result.Add(new BlockedTarget("port", text, $"{protocol}{text}{name} · {direction} · {who}"));
                }
            }

            if (AddressRange.TryParseList(r.Addresses, out var addresses, out _))
            {
                foreach (var a in addresses)
                {
                    result.Add(new BlockedTarget("address", a.Text, $"{a.Text} · {direction} · {who}"));
                }
            }
        }

        return result.DistinctBy(b => b.Label).OrderBy(b => b.Kind).ThenBy(b => b.Label, StringComparer.OrdinalIgnoreCase).ToList();
    }

    /// <summary>A network rule rebuilt with another action, direction and/or networks (to replace it), or null if it can't be.</summary>
    public static NetRule? Changed(RuleInfo rule, string? action = null, string? direction = null, string? networks = null)
    {
        ArgumentNullException.ThrowIfNull(rule);
        if (rule.Kind != nameof(FilterKind.NetRule) || !NetRule.TryParseProtocol(rule.Protocol ?? "any", out var protocol))
        {
            return null;
        }

        var newAction = (action ?? rule.Action) == "allow" ? RuleAction.Allow : RuleAction.Block;
        var newDirection = (direction ?? rule.Direction) switch
        {
            "in" => TrafficDirection.Inbound,
            "both" => TrafficDirection.Both,
            _ => TrafficDirection.Outbound,
        };
        return NetworkScope.TryParse(networks ?? rule.Networks, out var newNetworks)
            ? NetRule.Create(newAction, newDirection, protocol, rule.Ports, rule.Addresses, rule.App, out _, newNetworks)
            : null;
    }

    /// <summary>The other action: allow ↔ block.</summary>
    public static string Opposite(string? action) => action == "allow" ? "block" : "allow";
}

/// <summary>Splitting long text (paths) into lines for print.</summary>
public static class TextWrap
{
    /// <summary>
    /// Breaks a path into lines of at most <paramref name="max"/> characters, at backslashes where
    /// possible: "C:\Program Files\Vendor\App\bin\" / "app.exe".
    /// </summary>
    public static IReadOnlyList<string> Path(string? path, int max)
    {
        if (string.IsNullOrEmpty(path))
        {
            return [];
        }

        max = Math.Max(8, max);
        var lines = new List<string>();
        var line = string.Empty;
        foreach (var part in Split(path))
        {
            if (line.Length + part.Length <= max)
            {
                line += part;
                continue;
            }

            if (line.Length > 0)
            {
                lines.Add(line);
                line = string.Empty;
            }

            var rest = part;
            while (rest.Length > max)
            {
                lines.Add(rest[..max]);
                rest = rest[max..];
            }

            line = rest;
        }

        if (line.Length > 0)
        {
            lines.Add(line);
        }

        return lines;
    }

    /// <summary>"C:\a\b.exe" → "C:\", "a\", "b.exe".</summary>
    private static IEnumerable<string> Split(string path)
    {
        var start = 0;
        for (var i = 0; i < path.Length; i++)
        {
            if (path[i] is '\\' or '/')
            {
                yield return path[start..(i + 1)];
                start = i + 1;
            }
        }

        if (start < path.Length)
        {
            yield return path[start..];
        }
    }
}
