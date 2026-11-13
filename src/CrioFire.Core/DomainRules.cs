using System.Globalization;
using System.Net;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace CrioFire.Core;

/// <summary>
/// A rule for a domain name: <c>example.com</c> covers example.com and every name under it
/// (www.example.com, a.b.example.com). The filtering platform only sees addresses, so the service
/// watches Windows' name lookups and, for each name a rule covers, adds a filter for the addresses
/// the lookup returned (see <see cref="DomainKeeper"/>). Outgoing connections only.
/// </summary>
/// <param name="Id">Stable id, also in each address filter's description.</param>
/// <param name="Domain">The normalized domain: lower case, no "*." and no trailing dot, international names as punycode.</param>
/// <param name="AppPath">Only for this program; null for every program.</param>
/// <param name="Managed">Set by the organization's policy.</param>
public sealed record DomainRule(
    string Id,
    string Domain,
    RuleAction Action,
    string? AppPath = null,
    NetworkProfiles Networks = NetworkProfiles.Any,
    bool Managed = false)
{
    /// <summary>True for <see cref="Domain"/> itself and any name under it.</summary>
    public bool Covers(string name) => DomainNames.Covers(Domain, name);

    /// <summary>"block example.com" (with " for chrome.exe", " on public networks").</summary>
    public string Summary()
    {
        var text = $"{RuleDescription.ActionText(Action)} {Domain}";
        if (AppPath is not null)
        {
            text += $" for {AppPath[(AppPath.LastIndexOfAny(['\\', '/']) + 1)..]}";
        }

        return NetworkScope.Normalize(Networks) == NetworkProfiles.Any ? text : $"{text} on {NetworkScope.Label(Networks)}";
    }

    /// <summary>The network rule an address filter for this domain is built from.</summary>
    public NetRule? ForAddress(IPAddress address, out string? error) =>
        NetRule.Create(Action, TrafficDirection.Outbound, NetProtocol.Any, null, address.ToString(), AppPath, out error, Networks);
}

/// <summary>Domain names: normalizing what people type, and matching names against a domain.</summary>
public static class DomainNames
{
    private static readonly IdnMapping Idn = new();

    /// <summary>
    /// "*.Example.COM." → "example.com"; "https://www.example.com/path" → "www.example.com";
    /// international names → punycode. Null and an error for anything that is not a domain name.
    /// </summary>
    public static string? Normalize(string? text, out string? error)
    {
        error = null;
        var name = text?.Trim() ?? string.Empty;
        if (name.Contains("://", StringComparison.Ordinal))
        {
            name = Uri.TryCreate(name, UriKind.Absolute, out var uri) ? uri.Host : name;
        }

        if (name.StartsWith("*.", StringComparison.Ordinal))
        {
            name = name[2..];
        }

        name = name.TrimEnd('.').ToLowerInvariant();
        try
        {
            name = name.Length == 0 ? name : Idn.GetAscii(name);
        }
        catch (ArgumentException)
        {
            error = $"'{text}' is not a domain name.";
            return null;
        }

        if (name.Length is 0 or > 253 || IPAddress.TryParse(name, out _))
        {
            error = name.Length == 0 ? "Enter a domain name, e.g. example.com." : $"'{text}' is an address, not a domain name: use a port and address rule.";
            return null;
        }

        var labels = name.Split('.');
        if (labels.Length < 2 && name != "localhost"
            || labels.Any(l => l.Length is 0 or > 63 || l.StartsWith('-') || l.EndsWith('-') || !l.All(c => c is (>= 'a' and <= 'z') or (>= '0' and <= '9') or '-' or '_')))
        {
            error = $"'{text}' is not a domain name (e.g. example.com).";
            return null;
        }

        return name;
    }

    /// <summary>True when <paramref name="name"/> is <paramref name="domain"/> or a name under it.</summary>
    public static bool Covers(string domain, string? name)
    {
        if (string.IsNullOrEmpty(name))
        {
            return false;
        }

        name = name.TrimEnd('.');
        return name.Equals(domain, StringComparison.OrdinalIgnoreCase)
            || (name.Length > domain.Length + 1
                && name.EndsWith(domain, StringComparison.OrdinalIgnoreCase)
                && name[name.Length - domain.Length - 1] == '.');
    }
}

/// <summary>
/// The filter for one address a domain rule's names resolved to. Description:
/// <c>criofire:v1|dom|block@public|&lt;rule id&gt;|93.184.216.34|C:\app.exe or *</c>.
/// </summary>
public sealed record DomainAddress(string RuleId, RuleAction Action, NetworkProfiles Networks, IPAddress Address, string? AppPath)
{
    public const string Tag = "dom";

    public string Format() =>
        string.Join('|', RuleDescription.Prefix, Tag, NetworkScope.ActionField(Action, Networks), RuleId, Address.ToString(), AppPath ?? "*");

    public static bool TryParse(string? description, out DomainAddress? address)
    {
        address = null;
        var parts = description?.Split('|', 6);
        if (parts is not { Length: 6 } || parts[0] != RuleDescription.Prefix || parts[1] != Tag
            || !NetworkScope.TryParseActionField(parts[2], out var action, out var networks)
            || parts[3].Length == 0 || !IPAddress.TryParse(parts[4], out var ip))
        {
            return false;
        }

        address = new DomainAddress(parts[3], action, networks, ip, parts[5] == "*" ? null : parts[5]);
        return true;
    }
}

/// <summary>%ProgramData%\criofire\domain-rules.json: the domain rules (the address filters come and go).</summary>
public sealed class DomainRuleStore(string path)
{
    private readonly object _gate = new();

    public static string DefaultPath => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "criofire", "domain-rules.json");

    public string FilePath { get; } = path;

    public IReadOnlyList<DomainRule> List()
    {
        lock (_gate)
        {
            try
            {
                return File.Exists(FilePath)
                    ? JsonSerializer.Deserialize(File.ReadAllText(FilePath), DomainRuleJson.Default.ListDomainRule) ?? []
                    : [];
            }
            catch (JsonException)
            {
                return [];
            }
        }
    }

    /// <summary>When the file last changed (so the service notices rules added through the API).</summary>
    public DateTime Changed => File.Exists(FilePath) ? File.GetLastWriteTimeUtc(FilePath) : DateTime.MinValue;

    /// <summary>Adds a rule, or replaces the one for the same domain and program (and owner: user or organization).</summary>
    public DomainRule Set(string domain, RuleAction action, string? appPath, NetworkProfiles networks, bool managed = false)
    {
        lock (_gate)
        {
            var normalized = DomainNames.Normalize(domain, out var error) ?? throw new ArgumentException(error);
            var rules = List().ToList();
            var existing = rules.FindIndex(r => Same(r, normalized, appPath, managed));
            var rule = new DomainRule(existing >= 0 ? rules[existing].Id : NewId(), normalized, action, appPath, NetworkScope.Normalize(networks), managed);
            if (existing >= 0)
            {
                rules[existing] = rule;
            }
            else
            {
                rules.Add(rule);
            }

            Save(rules);
            return rule;
        }
    }

    /// <summary>Removes the user's rules for a domain (for one program, or for all with <paramref name="anyProgram"/>). Returns how many.</summary>
    public int Remove(string domain, string? appPath = null, bool anyProgram = true)
    {
        lock (_gate)
        {
            var normalized = DomainNames.Normalize(domain, out var error) ?? throw new ArgumentException(error);
            var rules = List().ToList();
            var removed = rules.RemoveAll(r => !r.Managed && r.Domain == normalized
                && (anyProgram || string.Equals(r.AppPath, appPath, StringComparison.OrdinalIgnoreCase)));
            if (removed > 0)
            {
                Save(rules);
            }

            return removed;
        }
    }

    public bool RemoveById(string id)
    {
        lock (_gate)
        {
            var rules = List().ToList();
            var removed = rules.RemoveAll(r => r.Id == id) > 0;
            if (removed)
            {
                Save(rules);
            }

            return removed;
        }
    }

    /// <summary>Replaces every rule of one owner (the user's, or the organization's) at once.</summary>
    public void ReplaceAll(bool managed, IEnumerable<DomainRule> replacement)
    {
        lock (_gate)
        {
            var rules = List().Where(r => r.Managed != managed).ToList();
            rules.AddRange(replacement.Select(r => r with { Managed = managed, Id = string.IsNullOrEmpty(r.Id) ? NewId() : r.Id }));
            Save(rules);
        }
    }

    private static bool Same(DomainRule r, string domain, string? appPath, bool managed) =>
        r.Managed == managed && r.Domain == domain && string.Equals(r.AppPath, appPath, StringComparison.OrdinalIgnoreCase);

    public static string NewId() => Guid.NewGuid().ToString("N")[..12];

    private void Save(List<DomainRule> rules)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(FilePath)!);
        File.WriteAllText(FilePath + ".tmp", JsonSerializer.Serialize(rules, DomainRuleJson.Default.ListDomainRule));
        File.Move(FilePath + ".tmp", FilePath, overwrite: true);
    }
}

[JsonSourceGenerationOptions(WriteIndented = true, PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    UseStringEnumConverter = true, DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
[JsonSerializable(typeof(List<DomainRule>))]
internal sealed partial class DomainRuleJson : JsonSerializerContext;
