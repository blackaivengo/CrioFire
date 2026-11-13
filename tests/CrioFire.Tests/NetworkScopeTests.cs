using CrioFire.Cli;
using CrioFire.Core;
using CrioFire.Core.Api;

namespace CrioFire.Tests;

/// <summary>Rules for some kinds of network only (domain, private, public).</summary>
public class NetworkScopeTests
{
    private static readonly int[] Categories = [0, 1, 2];

    private static readonly DateTime Now = new(2026, 11, 13, 4, 0, 0, DateTimeKind.Utc);

    [Theory]
    [InlineData(null, NetworkProfiles.Any)]
    [InlineData("", NetworkProfiles.Any)]
    [InlineData("any", NetworkProfiles.Any)]
    [InlineData("public", NetworkProfiles.Public)]
    [InlineData("Private, Domain", NetworkProfiles.Private | NetworkProfiles.Domain)]
    [InlineData("home+work", NetworkProfiles.Private | NetworkProfiles.Domain)]
    [InlineData("domain,private,public", NetworkProfiles.Any)]   // all three = every network
    public void NetworksParse(string? text, NetworkProfiles expected)
    {
        Assert.True(NetworkScope.TryParse(text, out var networks));
        Assert.Equal(expected, networks);
    }

    [Theory]
    [InlineData("cafe")]
    [InlineData("public,lan")]
    public void UnknownNetworksAreRefused(string text) => Assert.False(NetworkScope.TryParse(text, out _));

    [Fact]
    public void NetworksHaveOneSpellingAndPlainLabels()
    {
        Assert.Equal("domain,private", NetworkScope.Text(NetworkProfiles.Private | NetworkProfiles.Domain));
        Assert.Equal("any", NetworkScope.Text(NetworkScope.All));
        Assert.Null(NetworkScope.TextOrNull(NetworkProfiles.Any));
        Assert.Equal("public networks", NetworkScope.Label(NetworkProfiles.Public));
        Assert.Equal("private and domain networks", NetworkScope.Label(NetworkProfiles.Private | NetworkProfiles.Domain));
        Assert.Equal("every network", NetworkScope.Label(NetworkProfiles.Any));
    }

    [Fact]
    public void ProfileIdsAreWhatTheFilteringPlatformUses()
    {
        // FWPM_CONDITION_CURRENT_PROFILE_ID: public 1, private 2, domain 3 (measured on a real public
        // network by the integration tests), one more than the Network List Manager's categories (0, 1, 2).
        Assert.True(NetworkScope.ProfileIds(NetworkProfiles.Public).SequenceEqual([1u]));
        Assert.True(NetworkScope.ProfileIds(NetworkProfiles.Domain | NetworkProfiles.Private).SequenceEqual([3u, 2u]));
        foreach (var category in Categories)
        {
            Assert.True(NetworkScope.ProfileIds(ConnectedNetworks.FromCategory(category)).SequenceEqual([(uint)category + 1]));
        }
        Assert.Empty(NetworkScope.ProfileIds(NetworkProfiles.Any));
        Assert.Empty(NetworkScope.ProfileIds(NetworkScope.All));
    }

    [Fact]
    public void ProgramRulesKeepTheirNetworksInTheDescription()
    {
        var rule = new RuleDescription(RuleAction.Block, TrafficDirection.Inbound, @"C:\Apps\chat.exe", NetworkProfiles.Public);

        Assert.Equal(@"criofire:v1|block@public|in|C:\Apps\chat.exe", rule.Format());
        Assert.True(RuleDescription.TryParse(rule.Format(), out var back));
        Assert.Equal(rule, back);
        Assert.Equal((FilterKind.AppRule, (FirewallMode?)null), FilterDescriptions.Classify(rule.Format()));
    }

    [Fact]
    public void RulesForEveryNetworkLookAsTheyAlwaysDid()
    {
        Assert.Equal(@"criofire:v1|allow|out|C:\a.exe", new RuleDescription(RuleAction.Allow, TrafficDirection.Outbound, @"C:\a.exe").Format());
        Assert.True(RuleDescription.TryParse(@"criofire:v1|allow|out|C:\a.exe", out var old));
        Assert.Equal(NetworkProfiles.Any, old!.Networks);
        Assert.False(RuleDescription.TryParse(@"criofire:v1|allow@|out|C:\a.exe", out _));
        Assert.False(RuleDescription.TryParse(@"criofire:v1|allow@cafe|out|C:\a.exe", out _));
    }

    [Fact]
    public void NetworkAndServiceRulesKeepTheirNetworks()
    {
        var net = NetRule.Create(RuleAction.Block, TrafficDirection.Inbound, NetProtocol.Tcp, "445", null, null, out var error, NetworkProfiles.Public)!;
        Assert.Null(error);
        Assert.Equal("criofire:v1|net|block@public|in|tcp|445|*|*", net.Format());
        Assert.True(NetRule.TryParse(net.Format(), out var netBack));
        Assert.Equal(net, netBack);
        Assert.Contains("on public networks", net.Summary(), StringComparison.Ordinal);
        Assert.Equal(FilterKind.NetRule, FilterDescriptions.Classify(net.Format()).Kind);

        var service = new ServiceRule(RuleAction.Allow, TrafficDirection.Outbound, "Dnscache", NetworkProfiles.Domain);
        Assert.Equal("criofire:v1|svc|allow@domain|out|Dnscache", service.Format());
        Assert.True(ServiceRule.TryParse(service.Format(), out var serviceBack));
        Assert.Equal(service, serviceBack);
        Assert.Equal(FilterKind.ServiceRule, FilterDescriptions.Classify(service.Format()).Kind);
    }

    [Fact]
    public void ExportedFilesCarryNetworksOnlyWhenARuleHasThem()
    {
        var filters = new List<CrioFireFilter>
        {
            new(1, "a", FilterLayers.ConnectV4, new RuleDescription(RuleAction.Block, TrafficDirection.Outbound, @"C:\a.exe", NetworkProfiles.Public)),
            new(2, "b", FilterLayers.ConnectV4, new RuleDescription(RuleAction.Allow, TrafficDirection.Outbound, @"C:\b.exe")),
            new(3, "s", FilterLayers.ConnectV4, null, FilterKind.ServiceRule, Service: new ServiceRule(RuleAction.Block, TrafficDirection.Outbound, "DiagTrack", NetworkProfiles.Public)),
        };

        var set = RuleBackup.FromFilters(filters, [], null, "PC", Now);
        var json = RuleBackup.ToJson(set);

        Assert.Equal("public", set.Programs.Single(p => p.App == @"C:\a.exe").Networks);
        Assert.Null(set.Programs.Single(p => p.App == @"C:\b.exe").Networks);
        Assert.Equal("public", Assert.Single(set.Services).Networks);
        Assert.Equal(2, json.Split("\"networks\"").Length - 1);   // only the two scoped rules
        Assert.Null(RuleBackup.Validate(RuleBackup.FromJson(json)));
    }

    [Fact]
    public void AnImportNoticesWhenOnlyTheNetworksChanged()
    {
        var current = new RuleSet
        {
            Programs = [new AppRuleEntry(@"C:\a.exe", "block", "out")],
            Services = [new ServiceRuleEntry("DiagTrack", "block", "out", "public")],
            Network = [new NetRuleEntry("block", "in", "tcp", "445", string.Empty, null, "domain,private")],
        };
        var incoming = new RuleSet
        {
            Programs = [new AppRuleEntry(@"C:\a.exe", "block", "out", "public")],
            Services = [new ServiceRuleEntry("DiagTrack", "block", "out", "Public")],
            Network = [new NetRuleEntry("block", "in", "tcp", "445", string.Empty, null, "private,domain")],
        };

        var plan = RuleBackup.Plan(current, incoming, ImportMode.Merge, _ => true);

        Assert.Equal(1, plan.Change);   // the program now only on public networks
        Assert.Equal(2, plan.Same);     // the same networks, written differently
        Assert.Equal(0, plan.Add);
    }

    [Fact]
    public void FilesWithUnknownNetworksAreRefused()
    {
        var set = new RuleSet { Programs = [new AppRuleEntry(@"C:\a.exe", "block", "out", "cafe")] };

        Assert.NotNull(RuleBackup.Validate(set));
        Assert.Null(RuleBackup.ToNetRule(new NetRuleEntry("block", "in", "tcp", "445", string.Empty, null, "lan"), out var error));
        Assert.NotNull(error);
    }

    [Fact]
    public void ChangingANetworkRuleKeepsOrChangesItsNetworks()
    {
        var info = new RuleInfo(7, nameof(FilterKind.NetRule), "block", "in", null, "inbound IPv4", "x", Protocol: "tcp", Ports: "445", Networks: "public");

        Assert.Equal(NetworkProfiles.Public, RuleViews.Changed(info, action: "allow")!.Networks);
        Assert.Equal(NetworkProfiles.Any, RuleViews.Changed(info, networks: "any")!.Networks);
        Assert.Equal(NetworkProfiles.Private | NetworkProfiles.Domain, RuleViews.Changed(info, networks: "domain,private")!.Networks);
    }

    [Fact]
    public void TheCommandLineTakesNetworks()
    {
        var program = CommandLine.Parse(["block", @"C:\a.exe", "--networks", "public"], out var error);
        Assert.Null(error);
        Assert.Equal(NetworkProfiles.Public, program.Networks);

        var net = CommandLine.Parse(["block", "--in", "--tcp", "--port", "445", "--networks", "domain,private"], out error);
        Assert.Null(error);
        Assert.Equal(NetworkProfiles.Domain | NetworkProfiles.Private, net.Net!.Networks);

        var service = CommandLine.Parse(["allow", "--service", "Dnscache", "--network", "work"], out error);
        Assert.Null(error);
        Assert.Equal(NetworkProfiles.Domain, service.Networks);

        CommandLine.Parse(["block", @"C:\a.exe", "--networks", "cafe"], out error);
        Assert.NotNull(error);
    }

    [Fact]
    public void ConnectedNetworksAreDescribedPlainly()
    {
        Assert.Equal(NetworkProfiles.Public, ConnectedNetworks.FromCategory(0));
        Assert.Equal(NetworkProfiles.Private, ConnectedNetworks.FromCategory(1));
        Assert.Equal(NetworkProfiles.Domain, ConnectedNetworks.FromCategory(2));
        Assert.Equal("Cafe (public)", ConnectedNetworks.Describe([new ConnectedNetwork("Cafe", NetworkProfiles.Public)]));
        Assert.Equal("Office (domain) and Home (private)",
            ConnectedNetworks.Describe([new ConnectedNetwork("Office", NetworkProfiles.Domain), new ConnectedNetwork("Home", NetworkProfiles.Private)]));
    }
}
