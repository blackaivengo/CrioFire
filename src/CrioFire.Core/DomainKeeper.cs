using System.Net;
using System.Net.Sockets;

namespace CrioFire.Core;

/// <summary>The address filters domain rules use (the filtering engine; a fake in tests).</summary>
public interface IDomainFilters
{
    IReadOnlyList<(ulong FilterId, DomainAddress Address)> ListDomainAddresses();

    /// <summary>Adds the filters for one address of a domain rule.</summary>
    void AddDomainAddress(DomainRule rule, IPAddress address);

    void RemoveFilters(IEnumerable<ulong> filterIds);
}

/// <summary>One completed name lookup: the name asked for, the names it led to (CNAMEs) and the addresses returned.</summary>
public sealed record DnsLookup(string Name, IReadOnlyList<string> Aliases, IReadOnlyList<IPAddress> Addresses)
{
    public IEnumerable<string> AllNames => Aliases.Prepend(Name);
}

/// <summary>
/// Keeps the address filters of domain rules in step with name lookups. When a lookup's name (or
/// one of its CNAMEs) is covered by a rule, the addresses it returned get a filter; an address no
/// lookup has returned for <see cref="Retention"/> loses it. When several rules cover a name, the
/// most specific domain wins (allow www.example.com beats block example.com for www.example.com).
/// </summary>
public sealed class DomainKeeper(IDomainFilters filters, Func<string, IReadOnlyList<IPAddress>> resolve)
{
    /// <summary>How long an address keeps its filter after the last lookup that returned it.</summary>
    public static readonly TimeSpan Retention = TimeSpan.FromHours(1);

    private readonly object _gate = new();
    private readonly Dictionary<(string RuleId, IPAddress Address), DateTime> _seen = [];
    private List<DomainRule> _rules = [];

    public IReadOnlyList<DomainRule> Rules
    {
        get
        {
            lock (_gate)
            {
                return [.. _rules];
            }
        }
    }

    /// <summary>How many addresses each rule has a filter for now, by rule id.</summary>
    public IReadOnlyDictionary<string, int> AddressCounts()
    {
        lock (_gate)
        {
            return _seen.Keys.GroupBy(k => k.RuleId).ToDictionary(g => g.Key, g => g.Count());
        }
    }

    /// <summary>Starts over (service start): removes every address filter, then looks up each rule's domain.</summary>
    public void Reset(IReadOnlyList<DomainRule> rules, DateTime nowUtc)
    {
        lock (_gate)
        {
            filters.RemoveFilters(filters.ListDomainAddresses().Select(f => f.FilterId));
            _seen.Clear();
            _rules = [.. rules];
            foreach (var rule in _rules)
            {
                Prime(rule, nowUtc);
            }
        }
    }

    /// <summary>The rules changed: removes the filters of rules that are gone or changed, and looks up the new ones.</summary>
    public void Update(IReadOnlyList<DomainRule> rules, DateTime nowUtc)
    {
        lock (_gate)
        {
            var kept = rules.Where(r => _rules.Contains(r)).Select(r => r.Id).ToHashSet();
            var stale = _seen.Keys.Where(k => !kept.Contains(k.RuleId)).ToList();
            RemoveKeys(stale);
            var added = rules.Where(r => !kept.Contains(r.Id)).ToList();
            _rules = [.. rules];
            foreach (var rule in added)
            {
                Prime(rule, nowUtc);
            }
        }
    }

    /// <summary>A lookup completed. Returns how many address filters were added.</summary>
    public int Observe(DnsLookup lookup, DateTime nowUtc)
    {
        ArgumentNullException.ThrowIfNull(lookup);
        var addresses = Usable(lookup.Addresses);
        if (addresses.Count == 0)
        {
            return 0;
        }

        lock (_gate)
        {
            var added = 0;
            foreach (var rule in Winners(lookup.AllNames.ToList()))
            {
                added += AddFor(rule, addresses, nowUtc);
            }

            return added;
        }
    }

    /// <summary>Removes the filters of addresses no lookup returned for <see cref="Retention"/>. Returns how many addresses.</summary>
    public int Sweep(DateTime nowUtc)
    {
        lock (_gate)
        {
            var old = _seen.Where(e => nowUtc - e.Value > Retention).Select(e => e.Key).ToList();
            RemoveKeys(old);
            return old.Count;
        }
    }

    /// <summary>
    /// The rules that decide for these names: for each program and set of networks, the rule with the
    /// longest domain covering any of them.
    /// </summary>
    private IEnumerable<DomainRule> Winners(List<string> names) =>
        _rules.Where(r => names.Any(r.Covers))
            .GroupBy(r => (App: r.AppPath?.ToUpperInvariant(), r.Networks, r.Managed))
            .Select(g => g.OrderByDescending(r => r.Domain.Length).First());

    private void Prime(DomainRule rule, DateTime nowUtc)
    {
        IReadOnlyList<IPAddress> found;
        try
        {
            found = resolve(rule.Domain);
        }
        catch (SocketException)
        {
            return;   // no such name (e.g. only its subdomains exist): lookups will add addresses later
        }

        // A more specific rule may cover the domain itself; it decides there.
        if (Winners([rule.Domain]).Contains(rule))
        {
            AddFor(rule, Usable(found), nowUtc);
        }
    }

    private int AddFor(DomainRule rule, List<IPAddress> addresses, DateTime nowUtc)
    {
        var added = 0;
        foreach (var address in addresses)
        {
            var key = (rule.Id, address);
            if (!_seen.ContainsKey(key))
            {
                try
                {
                    filters.AddDomainAddress(rule, address);
                    added++;
                }
                catch (Exception ex) when (ex is FileNotFoundException or ArgumentException or WfpException)
                {
                    // The program is gone or the engine refused: remembered anyway, so it is not retried on every lookup.
                }
            }

            _seen[key] = nowUtc;
        }

        return added;
    }

    private void RemoveKeys(List<(string RuleId, IPAddress Address)> keys)
    {
        if (keys.Count == 0)
        {
            return;
        }

        var set = keys.ToHashSet();
        filters.RemoveFilters(filters.ListDomainAddresses().Where(f => set.Contains((f.Address.RuleId, f.Address.Address))).Select(f => f.FilterId));
        foreach (var key in keys)
        {
            _seen.Remove(key);
        }
    }

    /// <summary>Real destinations only: not 0.0.0.0 or :: (what blocklisting DNS servers answer), not loopback.</summary>
    private static List<IPAddress> Usable(IEnumerable<IPAddress> addresses) =>
        addresses.Select(a => a.IsIPv4MappedToIPv6 ? a.MapToIPv4() : a)
            .Where(a => !IPAddress.IsLoopback(a) && !a.Equals(IPAddress.Any) && !a.Equals(IPAddress.IPv6Any) && !a.Equals(IPAddress.IPv6None))
            .Distinct()
            .ToList();
}
