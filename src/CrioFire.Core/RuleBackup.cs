using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace CrioFire.Core;

/// <summary>
/// Every rule a user made, as a portable file: program, network and service rules, the automatic
/// rules and the mode. Used for export and import, for automatic backups, and later by the admin
/// server to push rules to many PCs. Temporary rules are not included (they expire anyway).
/// </summary>
public sealed record RuleSet
{
    public const int CurrentFormat = 1;

    public int Format { get; init; } = CurrentFormat;

    public string Product { get; init; } = "CrioFire Private Firewall";

    public DateTime CreatedUtc { get; init; }

    public string? Computer { get; init; }

    /// <summary>learning, ask or allowlist.</summary>
    public string? Mode { get; init; }

    public List<AutoRuleSetting> AutoRules { get; init; } = [];

    public List<AppRuleEntry> Programs { get; init; } = [];

    public List<NetRuleEntry> Network { get; init; } = [];

    public List<ServiceRuleEntry> Services { get; init; } = [];

    /// <summary>Domain rules; null (left out of the file) when there are none, so older files and versions stay the same.</summary>
    public List<DomainRuleEntry>? Domains { get; init; }

    [JsonIgnore]
    public int Count => Programs.Count + Network.Count + Services.Count + (Domains?.Count ?? 0);
}

/// <summary>A program rule. App is a full path, "System" for the kernel, or "pkg:family" for a Store app.</summary>
/// <param name="Networks">The kinds of network the rule applies on ("public", "domain,private"); null for every network.</param>
public sealed record AppRuleEntry(string App, string Action, string Direction, string? Networks = null);

/// <param name="Networks">The kinds of network the rule applies on; null for every network.</param>
public sealed record NetRuleEntry(string Action, string Direction, string Protocol, string Ports, string Addresses, string? App, string? Networks = null);

/// <param name="Networks">The kinds of network the rule applies on; null for every network.</param>
public sealed record ServiceRuleEntry(string Service, string Action, string Direction, string? Networks = null);

/// <summary>A domain rule: the domain and every name under it, outgoing connections.</summary>
/// <param name="App">Only for this program; null for every program.</param>
/// <param name="Networks">The kinds of network the rule applies on; null for every network.</param>
public sealed record DomainRuleEntry(string Domain, string Action, string? App = null, string? Networks = null);

public sealed record AutoRuleSetting(string Name, bool Enabled);

/// <summary>Merge adds and updates rules and keeps the others; Replace also removes rules that are not in the file.</summary>
public enum ImportMode
{
    Merge,
    Replace,
}

/// <summary>What an import does (or would do, for a preview).</summary>
/// <param name="Missing">Programs in the file that are not on this PC; their rules are skipped.</param>
/// <param name="ModeChange">The mode the file asks for when it differs and the import applies the mode; otherwise null.</param>
public sealed record ImportPlan(int Add, int Change, int Same, int Remove, List<string> Missing, string? ModeChange = null)
{
    public int Total => Add + Change + Remove;
}

/// <summary>A saved backup, as listed.</summary>
public sealed record BackupInfo(string Name, DateTime CreatedUtc, string Reason, int Rules);

public static class RuleBackup
{
    /// <summary>The rules in a list of CrioFire filters, one entry per rule (not per filter).</summary>
    public static RuleSet FromFilters(
        IReadOnlyList<CrioFireFilter> filters,
        IEnumerable<AutoRuleSetting> autoRules,
        IEnumerable<string>? temporaryApps,
        string? computer,
        DateTime nowUtc,
        IEnumerable<DomainRule>? domainRules = null)
    {
        ArgumentNullException.ThrowIfNull(filters);
        ArgumentNullException.ThrowIfNull(autoRules);
        var temporary = (temporaryApps ?? []).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var mode = filters.FirstOrDefault(f => f.Kind == FilterKind.DefaultBlock)?.Mode ?? FirewallMode.Learning;

        var programs = filters
            .Where(f => !f.Managed && f.Kind == FilterKind.AppRule && f.Rule is not null && !temporary.Contains(f.Rule.AppPath))
            .Select(f => new AppRuleEntry(f.Rule!.AppPath, RuleDescription.ActionText(f.Rule.Action), RuleDescription.DirectionText(f.Rule.Direction), NetworkScope.TextOrNull(f.Rule.Networks)))
            .Distinct(AppEntryComparer.Instance)
            .OrderBy(e => e.App, StringComparer.OrdinalIgnoreCase).ThenBy(e => e.Direction, StringComparer.Ordinal)
            .ToList();
        var network = filters
            .Where(f => !f.Managed && f.Kind == FilterKind.NetRule && f.Net is not null)
            .Select(f => ToEntry(f.Net!))
            .Distinct()
            .OrderBy(e => e.App ?? string.Empty, StringComparer.OrdinalIgnoreCase).ThenBy(e => e.Ports, StringComparer.Ordinal).ThenBy(e => e.Addresses, StringComparer.Ordinal)
            .ToList();
        var services = filters
            .Where(f => !f.Managed && f.Kind == FilterKind.ServiceRule && f.Service is not null)
            .Select(f => new ServiceRuleEntry(f.Service!.ServiceName, RuleDescription.ActionText(f.Service.Action), RuleDescription.DirectionText(f.Service.Direction), NetworkScope.TextOrNull(f.Service.Networks)))
            .Distinct()
            .OrderBy(e => e.Service, StringComparer.OrdinalIgnoreCase)
            .ToList();
        var domains = (domainRules ?? [])
            .Where(d => !d.Managed)
            .Select(ToEntry)
            .OrderBy(e => e.Domain, StringComparer.Ordinal).ThenBy(e => e.App ?? string.Empty, StringComparer.OrdinalIgnoreCase)
            .ToList();

        return new RuleSet
        {
            CreatedUtc = nowUtc,
            Computer = computer,
            Mode = FilterDescriptions.ModeText(mode),
            AutoRules = autoRules.ToList(),
            Programs = programs,
            Network = network,
            Services = services,
            Domains = domains.Count == 0 ? null : domains,
        };
    }

    /// <summary>The rules in force on this PC now (with the domain rules, when <paramref name="domainRules"/> is given).</summary>
    public static RuleSet Export(WfpEngine engine, TemporaryRuleStore? temporaryRules, DateTime nowUtc, DomainRuleStore? domainRules = null)
    {
        ArgumentNullException.ThrowIfNull(engine);
        return FromFilters(
            engine.ListFilters(),
            engine.GetAutoRules().Select(r => new AutoRuleSetting(r.Name, r.Enabled)),
            temporaryRules?.All().Select(t => t.App),
            Environment.MachineName,
            nowUtc,
            domainRules?.List());
    }

    public static DomainRuleEntry ToEntry(DomainRule d)
    {
        ArgumentNullException.ThrowIfNull(d);
        return new DomainRuleEntry(d.Domain, RuleDescription.ActionText(d.Action), d.AppPath, NetworkScope.TextOrNull(d.Networks));
    }

    /// <summary>A file's domain rule as a rule (normalized); null and an error when it is not valid.</summary>
    public static DomainRule? ToDomainRule(DomainRuleEntry e, bool managed, out string? error)
    {
        ArgumentNullException.ThrowIfNull(e);
        var domain = DomainNames.Normalize(e.Domain, out error);
        if (domain is null)
        {
            return null;
        }

        if (!IsAction(e.Action) || !NetworkScope.TryParse(e.Networks, out var networks))
        {
            error = $"The rule for {e.Domain} is not valid.";
            return null;
        }

        return new DomainRule(string.Empty, domain, ParseAction(e.Action), string.IsNullOrWhiteSpace(e.App) ? null : e.App, networks, managed);
    }

    public static NetRuleEntry ToEntry(NetRule n)
    {
        ArgumentNullException.ThrowIfNull(n);
        return new NetRuleEntry(
            RuleDescription.ActionText(n.Action),
            RuleDescription.DirectionText(n.Direction),
            NetRule.ProtocolText(n.Protocol),
            n.Ports,
            n.Addresses,
            n.AppPath,
            NetworkScope.TextOrNull(n.Networks));
    }

    /// <summary>Checks a file's contents before anything is applied. Returns null when it is fine.</summary>
    public static string? Validate(RuleSet set)
    {
        ArgumentNullException.ThrowIfNull(set);
        if (set.Format > RuleSet.CurrentFormat)
        {
            return "This rules file was made by a newer version of CrioFire. Update CrioFire to import it.";
        }

        foreach (var p in set.Programs)
        {
            if (string.IsNullOrWhiteSpace(p.App) || !IsAction(p.Action) || !IsDirection(p.Direction) || !NetworkScope.TryParse(p.Networks, out _))
            {
                return $"A program rule in the file is not valid ({p.App}).";
            }
        }

        foreach (var s in set.Services)
        {
            if (string.IsNullOrWhiteSpace(s.Service) || !IsAction(s.Action) || !IsDirection(s.Direction) || !NetworkScope.TryParse(s.Networks, out _))
            {
                return $"A service rule in the file is not valid ({s.Service}).";
            }
        }

        foreach (var n in set.Network)
        {
            if (ToNetRule(n, out var error) is null)
            {
                return $"A network rule in the file is not valid: {error}";
            }
        }

        foreach (var d in set.Domains ?? [])
        {
            if (ToDomainRule(d, managed: false, out var error) is null)
            {
                return $"A domain rule in the file is not valid: {error}";
            }
        }

        if (set.Mode is not null && !FilterDescriptions.TryParseMode(set.Mode, out _))
        {
            return $"The mode in the file is not valid ({set.Mode}).";
        }

        return null;
    }

    /// <summary>Compares the rules in force with a file: what an import would add, change, keep and remove.</summary>
    public static ImportPlan Plan(RuleSet current, RuleSet incoming, ImportMode mode, Func<string, bool> programExists, bool applyMode = false)
    {
        ArgumentNullException.ThrowIfNull(current);
        ArgumentNullException.ThrowIfNull(incoming);
        ArgumentNullException.ThrowIfNull(programExists);
        int add = 0, change = 0, same = 0, remove = 0;
        var missing = new List<string>();

        var currentApps = current.Programs.ToDictionary(AppKey, Effect, StringComparer.OrdinalIgnoreCase);
        var incomingApps = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var p in incoming.Programs)
        {
            incomingApps.Add(AppKey(p));
            if (!IsAvailable(p.App, programExists))
            {
                missing.Add(p.App);
                continue;
            }

            if (!currentApps.TryGetValue(AppKey(p), out var action))
            {
                add++;
            }
            else if (!string.Equals(action, Effect(p), StringComparison.OrdinalIgnoreCase))
            {
                change++;
            }
            else
            {
                same++;
            }
        }

        var currentNet = current.Network.Select(Normal).ToHashSet();
        foreach (var n in incoming.Network)
        {
            if (currentNet.Contains(Normal(n)))
            {
                same++;
            }
            else
            {
                add++;
            }
        }

        var currentServices = current.Services.ToDictionary(ServiceKey, Effect, StringComparer.OrdinalIgnoreCase);
        foreach (var s in incoming.Services)
        {
            if (!currentServices.TryGetValue(ServiceKey(s), out var action))
            {
                add++;
            }
            else if (!string.Equals(action, Effect(s), StringComparison.OrdinalIgnoreCase))
            {
                change++;
            }
            else
            {
                same++;
            }
        }

        var currentDomains = (current.Domains ?? []).ToDictionary(DomainKey, Effect, StringComparer.OrdinalIgnoreCase);
        foreach (var d in incoming.Domains ?? [])
        {
            if (!currentDomains.TryGetValue(DomainKey(d), out var effect))
            {
                add++;
            }
            else if (!string.Equals(effect, Effect(d), StringComparison.OrdinalIgnoreCase))
            {
                change++;
            }
            else
            {
                same++;
            }
        }

        if (mode == ImportMode.Replace)
        {
            var incomingNet = incoming.Network.Select(Normal).ToHashSet();
            var incomingServices = incoming.Services.Select(ServiceKey).ToHashSet(StringComparer.OrdinalIgnoreCase);
            var incomingDomains = (incoming.Domains ?? []).Select(DomainKey).ToHashSet(StringComparer.OrdinalIgnoreCase);
            remove += current.Programs.Count(p => !incomingApps.Contains(AppKey(p)));
            remove += current.Network.Count(n => !incomingNet.Contains(Normal(n)));
            remove += current.Services.Count(s => !incomingServices.Contains(ServiceKey(s)));
            remove += (current.Domains ?? []).Count(d => !incomingDomains.Contains(DomainKey(d)));
        }

        var modeChange = applyMode && incoming.Mode is not null && !string.Equals(incoming.Mode, current.Mode, StringComparison.OrdinalIgnoreCase)
            ? incoming.Mode
            : null;
        return new ImportPlan(add, change, same, remove, missing.Distinct(StringComparer.OrdinalIgnoreCase).ToList(), modeChange);
    }

    /// <summary>
    /// Applies a rules file. Merge adds and updates; Replace also removes rules that are not in the
    /// file. Rules for programs that are not on this PC are skipped. The automatic rules are set as
    /// in the file; the mode only when <paramref name="applyMode"/> is true. Returns what was done.
    /// </summary>
    public static ImportPlan Apply(WfpEngine engine, RuleSet incoming, ImportMode mode, TemporaryRuleStore? temporaryRules, bool applyMode, DateTime nowUtc,
        DomainRuleStore? domainRules = null)
    {
        ArgumentNullException.ThrowIfNull(engine);
        ArgumentNullException.ThrowIfNull(incoming);
        if (Validate(incoming) is { } error)
        {
            throw new ArgumentException(error);
        }

        var current = Export(engine, temporaryRules, nowUtc, domainRules);
        var plan = Plan(current, incoming, mode, File.Exists, applyMode);
        var currentApps = current.Programs.ToDictionary(AppKey, Effect, StringComparer.OrdinalIgnoreCase);
        var currentServices = current.Services.ToDictionary(ServiceKey, Effect, StringComparer.OrdinalIgnoreCase);
        var currentNet = current.Network.Select(Normal).ToHashSet();

        if (mode == ImportMode.Replace)
        {
            var incomingApps = incoming.Programs.Select(AppKey).ToHashSet(StringComparer.OrdinalIgnoreCase);
            foreach (var p in current.Programs.Where(p => !incomingApps.Contains(AppKey(p))))
            {
                engine.RemoveAppRules(p.App, ParseDirection(p.Direction));
            }

            var incomingNet = incoming.Network.Select(Normal).ToHashSet();
            var filters = engine.ListFilters();
            foreach (var n in current.Network.Where(n => !incomingNet.Contains(Normal(n))))
            {
                var first = filters.FirstOrDefault(f => !f.Managed && f.Kind == FilterKind.NetRule && f.Net is not null && ToEntry(f.Net) == n);
                if (first is not null)
                {
                    engine.RemoveFilter(first.FilterId);   // removes all of that rule's filters
                }
            }

            var incomingServices = incoming.Services.Select(ServiceKey).ToHashSet(StringComparer.OrdinalIgnoreCase);
            foreach (var s in current.Services.Where(s => !incomingServices.Contains(ServiceKey(s))))
            {
                engine.RemoveServiceRules(s.Service, ParseDirection(s.Direction));
            }
        }

        foreach (var p in incoming.Programs)
        {
            if (!IsAvailable(p.App, File.Exists)
                || (currentApps.TryGetValue(AppKey(p), out var action) && string.Equals(action, Effect(p), StringComparison.OrdinalIgnoreCase)))
            {
                continue;
            }

            try
            {
                engine.SetAppRule(p.App, ParseAction(p.Action), ParseDirection(p.Direction), ParseNetworks(p.Networks));
            }
            catch (FileNotFoundException)
            {
                // Removed between the check and now; it is listed as missing anyway.
            }
        }

        foreach (var n in incoming.Network.Where(n => !currentNet.Contains(Normal(n))))
        {
            engine.AddNetRule(ToNetRule(n, out _)!);
        }

        // Domain rules live in their own file; the service turns them into address filters.
        if (domainRules is not null)
        {
            var wanted = (incoming.Domains ?? []).Select(d => ToDomainRule(d, managed: false, out _)!).ToList();
            if (mode == ImportMode.Replace)
            {
                var keep = wanted.Select(d => d.Domain + "|" + d.AppPath).ToHashSet(StringComparer.OrdinalIgnoreCase);
                foreach (var old in domainRules.List().Where(d => !d.Managed && !keep.Contains(d.Domain + "|" + d.AppPath)))
                {
                    domainRules.RemoveById(old.Id);
                }
            }

            foreach (var d in wanted)
            {
                domainRules.Set(d.Domain, d.Action, d.AppPath, d.Networks);
            }
        }

        foreach (var s in incoming.Services)
        {
            if (!currentServices.TryGetValue(ServiceKey(s), out var action) || !string.Equals(action, Effect(s), StringComparison.OrdinalIgnoreCase))
            {
                engine.SetServiceRule(s.Service, ParseAction(s.Action), ParseDirection(s.Direction), ParseNetworks(s.Networks));
            }
        }

        foreach (var auto in incoming.AutoRules)
        {
            if (AutoRulePolicy.IsKnown(auto.Name) && current.AutoRules.FirstOrDefault(a => string.Equals(a.Name, auto.Name, StringComparison.OrdinalIgnoreCase))?.Enabled != auto.Enabled)
            {
                engine.SetAutoRule(auto.Name, auto.Enabled);
            }
        }

        if (plan.ModeChange is { } newMode && FilterDescriptions.TryParseMode(newMode, out var parsed))
        {
            engine.SetMode(parsed);
        }

        return plan;
    }

    /// <summary>A fingerprint of the rules alone (not when or where they were exported), to notice changes.</summary>
    public static string Fingerprint(RuleSet set)
    {
        ArgumentNullException.ThrowIfNull(set);
        var content = set with { CreatedUtc = default, Computer = null };
        var json = JsonSerializer.Serialize(content, RuleSetJson.Default.RuleSet);
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(json)));
    }

    public static string ToJson(RuleSet set) => JsonSerializer.Serialize(set, RuleSetJson.Default.RuleSet);

    /// <summary>Reads a rules file; throws ArgumentException with a readable message when it is not one.</summary>
    public static RuleSet FromJson(string json)
    {
        try
        {
            var set = JsonSerializer.Deserialize(json, RuleSetJson.Default.RuleSet);
            if (set is null || set.Format < 1)
            {
                throw new ArgumentException("This is not a CrioFire rules file.");
            }

            return set;
        }
        catch (JsonException)
        {
            throw new ArgumentException("This is not a CrioFire rules file.");
        }
    }

    public static NetRule? ToNetRule(NetRuleEntry n, out string? error)
    {
        ArgumentNullException.ThrowIfNull(n);
        error = null;
        if (!IsAction(n.Action) || !IsDirection(n.Direction) || !NetRule.TryParseProtocol(n.Protocol, out var protocol))
        {
            error = "action, direction or protocol is not valid.";
            return null;
        }

        var ports = n.Ports is "*" ? null : n.Ports;
        var addresses = n.Addresses is "*" ? null : n.Addresses;
        if (!NetworkScope.TryParse(n.Networks, out var networks))
        {
            error = "networks must be any, or a list of domain, private and public.";
            return null;
        }

        return NetRule.Create(ParseAction(n.Action), ParseDirection(n.Direction), protocol, ports, addresses, n.App, out error, networks);
    }

    private static bool IsAvailable(string app, Func<string, bool> programExists) =>
        KnownApps.IsKernel(app) || StoreApps.IsPackage(app) || programExists(app);

    private static string AppKey(AppRuleEntry e) => e.App + "|" + e.Direction;

    /// <summary>What a rule does, for comparing: the action and the networks, e.g. "block@public".</summary>
    private static string Effect(AppRuleEntry e) => e.Action.ToLowerInvariant() + "@" + Networks(e.Networks);

    private static string Effect(ServiceRuleEntry e) => e.Action.ToLowerInvariant() + "@" + Networks(e.Networks);

    private static string Effect(DomainRuleEntry e) => e.Action.ToLowerInvariant() + "@" + Networks(e.Networks);

    private static string DomainKey(DomainRuleEntry e) => (DomainNames.Normalize(e.Domain, out _) ?? e.Domain) + "|" + e.App;

    /// <summary>A network rule with its networks written one way, so "Private,Domain" and "domain,private" compare equal.</summary>
    private static NetRuleEntry Normal(NetRuleEntry e) => e with { Networks = NetworkScope.TryParse(e.Networks, out var n) ? NetworkScope.TextOrNull(n) : e.Networks };

    private static string Networks(string? text) => NetworkScope.TryParse(text, out var n) ? NetworkScope.Text(n) : text ?? "any";

    public static NetworkProfiles ParseNetworks(string? text) => NetworkScope.TryParse(text, out var n) ? n : NetworkProfiles.Any;

    private static string ServiceKey(ServiceRuleEntry e) => e.Service + "|" + e.Direction;

    private static bool IsAction(string? text) => text?.ToLowerInvariant() is "block" or "allow";

    private static bool IsDirection(string? text) => text?.ToLowerInvariant() is "out" or "in" or "both";

    private static RuleAction ParseAction(string text) =>
        text.Equals("allow", StringComparison.OrdinalIgnoreCase) ? RuleAction.Allow : RuleAction.Block;

    private static TrafficDirection ParseDirection(string text) => text.ToLowerInvariant() switch
    {
        "in" => TrafficDirection.Inbound,
        "both" => TrafficDirection.Both,
        _ => TrafficDirection.Outbound,
    };

    private sealed class AppEntryComparer : IEqualityComparer<AppRuleEntry>
    {
        public static readonly AppEntryComparer Instance = new();

        public bool Equals(AppRuleEntry? x, AppRuleEntry? y) =>
            x is not null && y is not null
            && string.Equals(x.App, y.App, StringComparison.OrdinalIgnoreCase)
            && x.Action == y.Action && x.Direction == y.Direction && x.Networks == y.Networks;

        public int GetHashCode(AppRuleEntry obj) =>
            HashCode.Combine(StringComparer.OrdinalIgnoreCase.GetHashCode(obj.App), obj.Action, obj.Direction, obj.Networks);
    }
}

/// <summary>
/// Keeps rule backups in %ProgramData%\criofire\backups: automatic ones whenever the rules change,
/// and one before every import or "remove all rules". The newest <see cref="Keep"/> are kept.
/// </summary>
public sealed class RuleBackupStore(string folder)
{
    public const int Keep = 30;

    private static readonly Lock Gate = new();

    public static string DefaultFolder => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "criofire", "backups");

    public string Folder { get; } = folder;

    /// <summary>Saves a backup; returns its name. <paramref name="reason"/> is a short word: auto, before-import...</summary>
    public string Save(RuleSet set, string reason)
    {
        ArgumentNullException.ThrowIfNull(set);
        var safeReason = new string(reason.Where(c => char.IsAsciiLetterOrDigit(c) || c == '-').ToArray());
        lock (Gate)
        {
            Directory.CreateDirectory(Folder);
            var name = $"rules-{set.CreatedUtc:yyyyMMdd-HHmmss}-{safeReason}.json";
            var path = Path.Combine(Folder, name);
            for (var i = 2; File.Exists(path); i++)
            {
                name = $"rules-{set.CreatedUtc:yyyyMMdd-HHmmss}-{safeReason}-{i}.json";
                path = Path.Combine(Folder, name);
            }

            File.WriteAllText(path, RuleBackup.ToJson(set));
            Prune();
            return name;
        }
    }

    public IReadOnlyList<BackupInfo> List()
    {
        lock (Gate)
        {
            if (!Directory.Exists(Folder))
            {
                return [];
            }

            var list = new List<BackupInfo>();
            foreach (var path in Directory.EnumerateFiles(Folder, "rules-*.json"))
            {
                try
                {
                    var set = RuleBackup.FromJson(File.ReadAllText(path));
                    var name = Path.GetFileName(path);
                    list.Add(new BackupInfo(name, set.CreatedUtc, ReasonOf(name), set.Count));
                }
                catch (Exception ex) when (ex is ArgumentException or IOException)
                {
                    // Skip damaged files.
                }
            }

            return list.OrderByDescending(b => b.CreatedUtc).ThenByDescending(b => b.Name, StringComparer.Ordinal).ToList();
        }
    }

    /// <summary>Loads a backup by the name <see cref="List"/> gave; refuses anything that is not such a name.</summary>
    public RuleSet Load(string name)
    {
        if (string.IsNullOrWhiteSpace(name) || name.IndexOfAny(['\\', '/', ':']) >= 0 || name.Contains("..", StringComparison.Ordinal)
            || !name.StartsWith("rules-", StringComparison.Ordinal) || !name.EndsWith(".json", StringComparison.Ordinal))
        {
            throw new ArgumentException("No backup with that name.");
        }

        var path = Path.Combine(Folder, name);
        if (!File.Exists(path))
        {
            throw new ArgumentException("No backup with that name.");
        }

        return RuleBackup.FromJson(File.ReadAllText(path));
    }

    /// <summary>The newest backup's fingerprint, to save an automatic backup only when the rules changed.</summary>
    public string? LatestFingerprint()
    {
        var list = List();
        return list.Count == 0 ? null : RuleBackup.Fingerprint(Load(list[0].Name));
    }

    private static string ReasonOf(string name)
    {
        // rules-yyyyMMdd-HHmmss-reason[-n].json
        var core = name["rules-".Length..^".json".Length];
        return core.Length > 16 ? core[16..] : "backup";
    }

    private void Prune()
    {
        var files = Directory.EnumerateFiles(Folder, "rules-*.json").OrderByDescending(Path.GetFileName, StringComparer.Ordinal).ToList();
        foreach (var old in files.Skip(Keep))
        {
            File.Delete(old);
        }
    }
}

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase, WriteIndented = true, DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
[JsonSerializable(typeof(RuleSet))]
internal sealed partial class RuleSetJson : JsonSerializerContext
{
}
