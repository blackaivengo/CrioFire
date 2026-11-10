using System.Text.Json;
using System.Text.Json.Serialization;
using CrioFire.Core.Api;

namespace CrioFire.Core;

/// <summary>
/// Decides which blocked connections should become an alert in Ask mode: a program that was
/// stopped by the catch-all block (it has no rule yet), not already being asked about, and not
/// dismissed earlier in this session. Pure logic, unit-tested.
/// </summary>
public sealed class AlertTracker
{
    private readonly HashSet<string> _pending = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _dismissed = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Programs to ask about now, given recent blocked connections and the current rules.</summary>
    public IReadOnlyList<EventInfo> NewAlerts(IEnumerable<EventInfo> events, IEnumerable<RuleInfo> rules)
    {
        ArgumentNullException.ThrowIfNull(events);
        ArgumentNullException.ThrowIfNull(rules);

        var withRule = rules.Where(r => r.App is not null).Select(r => r.App!).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var alerts = new List<EventInfo>();
        foreach (var e in events.OrderBy(e => e.TimeUtc))
        {
            if (e.Kind != nameof(FilterKind.DefaultBlock) || string.IsNullOrEmpty(e.App))
            {
                continue;
            }

            if (withRule.Contains(e.App) || _pending.Contains(e.App) || _dismissed.Contains(e.App))
            {
                continue;
            }

            _pending.Add(e.App);
            alerts.Add(e);
        }

        return alerts;
    }

    /// <summary>The user chose Allow or Block: a rule now exists, so no more alerts come anyway.</summary>
    public void Decided(string app) => _pending.Remove(app);

    /// <summary>The user closed the alert without choosing: don't ask again until the app restarts.</summary>
    public void Dismissed(string app)
    {
        _pending.Remove(app);
        _dismissed.Add(app);
    }
}

/// <summary>An allow or block rule that CrioFire removes again when it expires.</summary>
public sealed record TemporaryRule(string App, string Direction, DateTime ExpiresUtc);

/// <summary>
/// Remembers temporary rules (e.g. "allow for 1 hour") in %ProgramData%\criofire\temporary-rules.json,
/// so they expire on time even across service restarts. Thread-safe.
/// </summary>
public sealed class TemporaryRuleStore(string path)
{
    private static readonly Lock Gate = new();

    public static string DefaultPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "criofire", "temporary-rules.json");

    public string FilePath { get; } = path;

    public IReadOnlyList<TemporaryRule> All()
    {
        lock (Gate)
        {
            return Load();
        }
    }

    /// <summary>Records (or replaces) the expiry for one program and direction.</summary>
    public void Add(TemporaryRule rule)
    {
        ArgumentNullException.ThrowIfNull(rule);
        lock (Gate)
        {
            var rules = Load().Where(r => !Same(r, rule.App, rule.Direction)).Append(rule).ToList();
            Save(rules);
        }
    }

    /// <summary>Forgets a program's temporary rules (it was made permanent or removed).</summary>
    public void Remove(string app)
    {
        lock (Gate)
        {
            var rules = Load();
            var kept = rules.Where(r => !string.Equals(r.App, app, StringComparison.OrdinalIgnoreCase)).ToList();
            if (kept.Count != rules.Count)
            {
                Save(kept);
            }
        }
    }

    /// <summary>Forgets every temporary rule (after panic or uninstall removed the filters).</summary>
    public void Clear()
    {
        lock (Gate)
        {
            if (File.Exists(FilePath))
            {
                File.Delete(FilePath);
            }
        }
    }

    /// <summary>Takes out the rules that have expired at <paramref name="nowUtc"/> and returns them.</summary>
    public IReadOnlyList<TemporaryRule> TakeExpired(DateTime nowUtc)
    {
        lock (Gate)
        {
            var rules = Load();
            var expired = rules.Where(r => r.ExpiresUtc <= nowUtc).ToList();
            if (expired.Count > 0)
            {
                Save(rules.Except(expired).ToList());
            }

            return expired;
        }
    }

    /// <summary>Removes the filters of expired temporary rules. Returns how many rules expired.</summary>
    public int ExpireDue(WfpEngine engine, DateTime nowUtc)
    {
        ArgumentNullException.ThrowIfNull(engine);
        var expired = TakeExpired(nowUtc);
        foreach (var rule in expired)
        {
            var direction = rule.Direction switch { "in" => TrafficDirection.Inbound, "both" => TrafficDirection.Both, _ => TrafficDirection.Outbound };
            engine.RemoveAppRules(rule.App, direction);
        }

        return expired.Count;
    }

    private static bool Same(TemporaryRule r, string app, string direction) =>
        string.Equals(r.App, app, StringComparison.OrdinalIgnoreCase) && r.Direction == direction;

    private List<TemporaryRule> Load()
    {
        if (!File.Exists(FilePath))
        {
            return [];
        }

        try
        {
            return JsonSerializer.Deserialize(File.ReadAllText(FilePath), TemporaryRuleJson.Default.ListTemporaryRule) ?? [];
        }
        catch (JsonException)
        {
            return [];   // a damaged file must not break the firewall; it is rewritten on the next change
        }
    }

    private void Save(List<TemporaryRule> rules)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(FilePath))!);
        var temp = FilePath + ".tmp";
        File.WriteAllText(temp, JsonSerializer.Serialize(rules, TemporaryRuleJson.Default.ListTemporaryRule));
        File.Move(temp, FilePath, overwrite: true);
    }
}

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase, WriteIndented = true)]
[JsonSerializable(typeof(List<TemporaryRule>))]
internal sealed partial class TemporaryRuleJson : JsonSerializerContext
{
}
