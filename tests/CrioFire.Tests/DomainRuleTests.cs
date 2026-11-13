using System.Net;
using System.Net.Sockets;
using System.Text;
using CrioFire.Cli;
using CrioFire.Core;

namespace CrioFire.Tests;

/// <summary>Domain rules: names, address filters, the store, following lookups, and files.</summary>
public sealed class DomainRuleTests : IDisposable
{
    private static readonly DateTime Now = new(2026, 11, 13, 20, 0, 0, DateTimeKind.Utc);
    private static readonly IPAddress A1 = IPAddress.Parse("203.0.113.1");
    private static readonly IPAddress A2 = IPAddress.Parse("203.0.113.2");
    private static readonly IPAddress A3 = IPAddress.Parse("2001:db8::3");

    private readonly string _dir = Path.Combine(Path.GetTempPath(), "criofire-domains-" + Guid.NewGuid().ToString("N"));

    public void Dispose()
    {
        if (Directory.Exists(_dir))
        {
            Directory.Delete(_dir, recursive: true);
        }
    }

    [Theory]
    [InlineData("example.com", "example.com")]
    [InlineData("*.Example.COM.", "example.com")]
    [InlineData("https://www.example.com/path?q=1", "www.example.com")]
    [InlineData("bücher.de", "xn--bcher-kva.de")]
    [InlineData("ads_server.example.net", "ads_server.example.net")]
    public void DomainsAreNormalized(string text, string expected)
    {
        Assert.Equal(expected, DomainNames.Normalize(text, out var error));
        Assert.Null(error);
    }

    [Theory]
    [InlineData("")]
    [InlineData("com")]
    [InlineData("203.0.113.5")]
    [InlineData("exa mple.com")]
    [InlineData("-bad.example.com")]
    [InlineData("a..b.com")]
    public void NonDomainsAreRefused(string text)
    {
        Assert.Null(DomainNames.Normalize(text, out var error));
        Assert.NotNull(error);
    }

    [Fact]
    public void ADomainCoversItselfAndNamesUnderIt()
    {
        Assert.True(DomainNames.Covers("example.com", "example.com"));
        Assert.True(DomainNames.Covers("example.com", "www.example.com."));
        Assert.True(DomainNames.Covers("example.com", "A.B.Example.Com"));
        Assert.False(DomainNames.Covers("example.com", "notexample.com"));
        Assert.False(DomainNames.Covers("example.com", "example.com.evil.net"));
        Assert.False(DomainNames.Covers("www.example.com", "example.com"));
        Assert.False(DomainNames.Covers("example.com", null));
    }

    [Fact]
    public void AddressFiltersDescribeTheirRule()
    {
        var address = new DomainAddress("abc123", RuleAction.Block, NetworkProfiles.Public, A3, @"C:\Apps\x.exe");

        Assert.Equal(@"criofire:v1|dom|block@public|abc123|2001:db8::3|C:\Apps\x.exe", address.Format());
        Assert.True(DomainAddress.TryParse(address.Format(), out var back));
        Assert.Equal(address, back);
        Assert.Equal(FilterKind.DomainAddress, FilterDescriptions.Classify(address.Format()).Kind);
        Assert.True(DomainAddress.TryParse("criofire:v1|dom|allow|r1|203.0.113.1|*", out var any));
        Assert.Null(any!.AppPath);
        Assert.False(DomainAddress.TryParse("criofire:v1|dom|allow|r1|not-an-ip|*", out _));
    }

    [Fact]
    public void TheStoreKeepsOneRulePerDomainProgramAndOwner()
    {
        var store = new DomainRuleStore(Path.Combine(_dir, "domain-rules.json"));

        var first = store.Set("Example.com", RuleAction.Block, null, NetworkProfiles.Any);
        var replaced = store.Set("example.com", RuleAction.Allow, null, NetworkProfiles.Public);
        store.Set("example.com", RuleAction.Block, @"C:\a.exe", NetworkProfiles.Any);
        store.ReplaceAll(managed: true, [new DomainRule(string.Empty, "tracker.net", RuleAction.Block)]);

        Assert.Equal(first.Id, replaced.Id);
        var rules = new DomainRuleStore(store.FilePath).List();
        Assert.Equal(3, rules.Count);
        Assert.Contains(rules, r => r is { Domain: "example.com", Action: RuleAction.Allow, Networks: NetworkProfiles.Public, AppPath: null });
        Assert.Contains(rules, r => r.Managed && r.Domain == "tracker.net" && r.Id.Length > 0);

        Assert.Equal(2, store.Remove("example.com"));
        Assert.Equal(0, store.Remove("tracker.net"));   // the organization's rule stays
        store.ReplaceAll(managed: true, []);
        Assert.Empty(store.List());
    }

    [Fact]
    public void LookupsOfCoveredNamesAddTheirAddresses()
    {
        var engine = new FakeFilters();
        var keeper = new DomainKeeper(engine, _ => [A1]);
        var rule = Rule("r1", "example.com");

        keeper.Reset([rule], Now);
        Assert.Equal([A1], engine.Addresses("r1"));   // the domain itself, looked up at once

        Assert.Equal(2, keeper.Observe(Lookup("cdn.example.com", A2, A3), Now));
        Assert.Equal(0, keeper.Observe(Lookup("www.other.org", IPAddress.Parse("198.51.100.7")), Now));
        Assert.Equal(0, keeper.Observe(Lookup("www.example.com", A2), Now));   // already there
        Assert.Equal(new[] { A1, A2, A3 }.OrderBy(a => a.ToString()), engine.Addresses("r1").OrderBy(a => a.ToString()));
    }

    [Fact]
    public void ACnameCoveredByARuleCountsToo()
    {
        var engine = new FakeFilters();
        var keeper = new DomainKeeper(engine, _ => []);
        keeper.Reset([Rule("r1", "tracker.net")], Now);

        keeper.Observe(new DnsLookup("innocent-looking.example.com", ["edge.tracker.net"], [A1]), Now);

        Assert.Equal([A1], engine.Addresses("r1"));
    }

    [Fact]
    public void TheMostSpecificDomainDecides()
    {
        var engine = new FakeFilters();
        var keeper = new DomainKeeper(engine, _ => []);
        keeper.Reset([Rule("block", "example.com"), Rule("allow", "www.example.com", RuleAction.Allow)], Now);

        keeper.Observe(Lookup("www.example.com", A1), Now);
        keeper.Observe(Lookup("mail.example.com", A2), Now);

        Assert.Equal([A1], engine.Addresses("allow"));
        Assert.Equal([A2], engine.Addresses("block"));
    }

    [Fact]
    public void BlocklistAnswersAndLoopbackAreIgnored()
    {
        var engine = new FakeFilters();
        var keeper = new DomainKeeper(engine, _ => []);
        keeper.Reset([Rule("r1", "example.com")], Now);

        var added = keeper.Observe(Lookup("example.com", IPAddress.Any, IPAddress.IPv6Any, IPAddress.Loopback, IPAddress.Parse("::ffff:203.0.113.1")), Now);

        Assert.Equal(1, added);
        Assert.Equal([A1], engine.Addresses("r1"));   // the IPv4-mapped address, as IPv4
    }

    [Fact]
    public void AddressesNotLookedUpForAnHourAreDropped()
    {
        var engine = new FakeFilters();
        var keeper = new DomainKeeper(engine, _ => []);
        keeper.Reset([Rule("r1", "example.com")], Now);
        keeper.Observe(Lookup("a.example.com", A1), Now);
        keeper.Observe(Lookup("b.example.com", A2), Now.AddMinutes(30));

        Assert.Equal(0, keeper.Sweep(Now.AddMinutes(59)));
        keeper.Observe(Lookup("a.example.com", A1), Now.AddMinutes(59));   // seen again: kept
        Assert.Equal(1, keeper.Sweep(Now.AddMinutes(91)));

        Assert.Equal([A1], engine.Addresses("r1"));
    }

    [Fact]
    public void ChangedOrRemovedRulesLoseTheirAddresses()
    {
        var engine = new FakeFilters();
        var keeper = new DomainKeeper(engine, d => d == "new.org" ? [A3] : []);
        var a = Rule("a", "example.com");
        var b = Rule("b", "example.net");
        keeper.Reset([a, b], Now);
        keeper.Observe(Lookup("example.com", A1), Now);
        keeper.Observe(Lookup("example.net", A2), Now);

        keeper.Update([a with { Action = RuleAction.Allow }, Rule("c", "new.org")], Now);

        Assert.Empty(engine.Addresses("a"));   // changed: starts over with the next lookup
        Assert.Empty(engine.Addresses("b"));   // removed
        Assert.Equal([A3], engine.Addresses("c"));
        keeper.Observe(Lookup("example.com", A1), Now);
        Assert.Equal(RuleAction.Allow, engine.Filters.Single(f => f.Address.RuleId == "a").Address.Action);
    }

    [Fact]
    public void StartingOverRemovesEveryOldAddressFilter()
    {
        var engine = new FakeFilters();
        engine.AddDomainAddress(Rule("old", "gone.com"), A1);
        var keeper = new DomainKeeper(engine, _ => throw new SocketException());

        keeper.Reset([Rule("r1", "example.com")], Now);

        Assert.Empty(engine.Filters);
    }

    [Fact]
    public void QueryResultsAreParsedAsTheDnsClientWritesThem()
    {
        var (aliases, addresses) = DnsClientEvents.ParseResults("type:  5 www.example.com.edgekey.net;type:  5 e1.a.akamaiedge.net;::ffff:93.184.216.34;2606:2800:220:1::1;");

        Assert.Equal(["www.example.com.edgekey.net", "e1.a.akamaiedge.net"], aliases);
        Assert.Equal([IPAddress.Parse("93.184.216.34"), IPAddress.Parse("2606:2800:220:1::1")], addresses);
        Assert.Empty(DnsClientEvents.ParseResults(null).Addresses);
    }

    [Fact]
    public void QueryCompletedEventsAreRead()
    {
        var lookup = DnsClientEvents.ParseQueryCompleted(Event3008("WWW.Example.com", 0, "::ffff:203.0.113.1;"));

        Assert.NotNull(lookup);
        Assert.Equal("www.example.com", lookup.Name);
        Assert.Equal([A1], lookup.Addresses);
        Assert.Null(DnsClientEvents.ParseQueryCompleted(Event3008("example.com", 9003, string.Empty)));   // failed lookup
        Assert.Null(DnsClientEvents.ParseQueryCompleted(Event3008("example.com", 0, "type:  5 x.net;")));   // no address
        Assert.Null(DnsClientEvents.ParseQueryCompleted(Encoding.Unicode.GetBytes("truncated")));
        Assert.Null(DnsClientEvents.ParseQueryCompleted([]));
    }

    [Fact]
    public void DomainRulesGoIntoFilesOnlyWhenThereAreSome()
    {
        var none = RuleBackup.FromFilters([], [], null, "PC", Now, []);
        var some = RuleBackup.FromFilters([], [], null, "PC", Now,
            [Rule("r1", "example.com"), Rule("r2", "corp.example", RuleAction.Allow) with { Managed = true }]);

        Assert.Null(none.Domains);
        Assert.DoesNotContain("domains", RuleBackup.ToJson(none), StringComparison.Ordinal);
        var entry = Assert.Single(some.Domains!);   // the organization's rule is not the user's to export
        Assert.Equal(new DomainRuleEntry("example.com", "block"), entry);
        Assert.Equal(1, some.Count);
        Assert.Null(RuleBackup.Validate(RuleBackup.FromJson(RuleBackup.ToJson(some))));
        Assert.NotNull(RuleBackup.Validate(new RuleSet { Domains = [new DomainRuleEntry("not a domain", "block")] }));
    }

    [Fact]
    public void AnImportPlansDomainRules()
    {
        var current = new RuleSet { Domains = [new DomainRuleEntry("example.com", "block"), new DomainRuleEntry("old.net", "block")] };
        var incoming = new RuleSet { Domains = [new DomainRuleEntry("*.Example.com", "block", Networks: "public"), new DomainRuleEntry("new.org", "allow")] };

        var merge = RuleBackup.Plan(current, incoming, ImportMode.Merge, _ => true);
        var replace = RuleBackup.Plan(current, incoming, ImportMode.Replace, _ => true);

        Assert.Equal((1, 1, 0), (merge.Add, merge.Change, merge.Remove));
        Assert.Equal(1, replace.Remove);
    }

    [Fact]
    public void TheCommandLineTakesDomains()
    {
        var block = CommandLine.Parse(["block", "--domain", "*.DoubleClick.net"], out var error);
        Assert.Null(error);
        Assert.Equal("doubleclick.net", block.Domain);
        Assert.Equal(CommandKind.Block, block.Kind);

        var forApp = CommandLine.Parse(["allow", "--domain", "corp.example", @"C:\Apps\x.exe", "--networks", "domain"], out error);
        Assert.Null(error);
        Assert.Equal(@"C:\Apps\x.exe", forApp.AppPath);
        Assert.Equal(NetworkProfiles.Domain, forApp.Networks);

        Assert.Equal(CommandKind.Unblock, CommandLine.Parse(["unblock", "--domain", "example.com"], out _).Kind);
        Assert.Equal(CommandKind.Domains, CommandLine.Parse(["domains"], out _).Kind);
        CommandLine.Parse(["block", "--domain", "example.com", "--port", "443"], out error);
        Assert.NotNull(error);
        CommandLine.Parse(["block", "--domain", "203.0.113.5"], out error);
        Assert.NotNull(error);
    }

    private static DomainRule Rule(string id, string domain, RuleAction action = RuleAction.Block) => new(id, domain, action);

    private static DnsLookup Lookup(string name, params IPAddress[] addresses) => new(name, [], addresses);

    /// <summary>Event 3008's data: QueryName, QueryType, QueryOptions, QueryStatus, QueryResults.</summary>
    private static byte[] Event3008(string name, uint status, string results)
    {
        var bytes = new List<byte>();
        bytes.AddRange(Encoding.Unicode.GetBytes(name + "\0"));
        bytes.AddRange(BitConverter.GetBytes(1u));
        bytes.AddRange(BitConverter.GetBytes(0x2000_0000_0000UL));
        bytes.AddRange(BitConverter.GetBytes(status));
        bytes.AddRange(Encoding.Unicode.GetBytes(results + "\0"));
        return [.. bytes];
    }

    private sealed class FakeFilters : IDomainFilters
    {
        private ulong _next = 1;

        public List<(ulong FilterId, DomainAddress Address)> Filters { get; } = [];

        public IReadOnlyList<(ulong FilterId, DomainAddress Address)> ListDomainAddresses() => [.. Filters];

        public void AddDomainAddress(DomainRule rule, IPAddress address) =>
            Filters.Add((_next++, new DomainAddress(rule.Id, rule.Action, rule.Networks, address, rule.AppPath)));

        public void RemoveFilters(IEnumerable<ulong> filterIds)
        {
            var ids = filterIds.ToHashSet();
            Filters.RemoveAll(f => ids.Contains(f.FilterId));
        }

        public List<IPAddress> Addresses(string ruleId) => Filters.Where(f => f.Address.RuleId == ruleId).Select(f => f.Address.Address).ToList();
    }
}
