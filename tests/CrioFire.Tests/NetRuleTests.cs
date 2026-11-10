using System.Net;
using System.Runtime.CompilerServices;
using CrioFire.Cli;
using CrioFire.Core;
using CrioFire.Core.Api;
using CrioFire.Core.Interop;

namespace CrioFire.Tests;

public class NetRuleTests
{
    [Theory]
    [InlineData("445", "445")]
    [InlineData("80, 443", "80,443")]
    [InlineData("8000-8100,22", "8000-8100,22")]
    [InlineData("*", "")]
    [InlineData("", "")]
    public void ParsesPorts(string text, string expected)
    {
        Assert.True(PortRange.TryParseList(text, out var ports, out var error), error);
        Assert.Equal(expected, string.Join(',', ports));
    }

    [Theory]
    [InlineData("0")]
    [InlineData("65536")]
    [InlineData("100-50")]
    [InlineData("http")]
    [InlineData("-5")]
    public void RejectsBadPorts(string text)
    {
        Assert.False(PortRange.TryParseList(text, out _, out var error));
        Assert.NotNull(error);
    }

    [Theory]
    [InlineData("10.0.0.0/8", "10.0.0.0", "10.255.255.255")]
    [InlineData("192.168.1.77/24", "192.168.1.0", "192.168.1.255")]
    [InlineData("203.0.113.5", "203.0.113.5", "203.0.113.5")]
    [InlineData("10.0.0.1-10.0.0.50", "10.0.0.1", "10.0.0.50")]
    [InlineData("0.0.0.0/0", "0.0.0.0", "255.255.255.255")]
    [InlineData("2001:db8::/32", "2001:db8::", "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff")]
    [InlineData("::1", "::1", "::1")]
    public void ParsesAddresses(string text, string low, string high)
    {
        Assert.True(AddressRange.TryParse(text, out var range));
        Assert.Equal(IPAddress.Parse(low), range!.Low);
        Assert.Equal(IPAddress.Parse(high), range.High);
    }

    [Theory]
    [InlineData("10.0.0.0/33")]
    [InlineData("10.0.0.50-10.0.0.1")]
    [InlineData("10.0.0.1-::1")]
    [InlineData("example.com")]
    [InlineData("10.0.0/8")]
    public void RejectsBadAddresses(string text) => Assert.False(AddressRange.TryParse(text, out _));

    [Fact]
    public void RangesKnowWhatTheyContain()
    {
        AddressRange.TryParse("10.0.0.0/8", out var net);
        Assert.True(net!.Contains(IPAddress.Parse("10.200.1.1")));
        Assert.True(net.Contains(IPAddress.Parse("::ffff:10.1.2.3")));
        Assert.False(net.Contains(IPAddress.Parse("11.0.0.0")));
        Assert.False(net.Contains(IPAddress.IPv6Loopback));
    }

    [Fact]
    public void DescriptionRoundTrips()
    {
        var rule = NetRule.Create(RuleAction.Block, TrafficDirection.Inbound, NetProtocol.Tcp, "445, 139", "10.0.0.0/8", null, out var error)!;
        Assert.Null(error);
        Assert.Equal("criofire:v1|net|block|in|tcp|445,139|10.0.0.0/8|*", rule.Format());
        Assert.True(NetRule.TryParse(rule.Format(), out var back));
        Assert.Equal(rule, back);

        var withApp = NetRule.Create(RuleAction.Allow, TrafficDirection.Outbound, NetProtocol.Any, "443", null, @"C:\Apps\a|b.exe", out _)!;
        Assert.True(NetRule.TryParse(withApp.Format(), out var back2));
        Assert.Equal(withApp.AppPath, back2!.AppPath);
        Assert.Equal(string.Empty, back2.Addresses);
    }

    [Theory]
    [InlineData("criofire:v1|net|block|in|tcp|445|*")]
    [InlineData("criofire:v1|net|maybe|in|tcp|445|*|*")]
    [InlineData("criofire:v1|net|block|up|tcp|445|*|*")]
    [InlineData("criofire:v1|net|block|in|icmp|*|*|*")]
    [InlineData("criofire:v1|net|block|in|tcp|99999|*|*")]
    [InlineData("criofire:v1|block|out|C:\\a.exe")]
    public void RejectsBadDescriptions(string text) => Assert.False(NetRule.TryParse(text, out _));

    [Fact]
    public void ClassifiesNetRules()
    {
        Assert.Equal(FilterKind.NetRule, FilterDescriptions.Classify("criofire:v1|net|block|in|tcp|445|*|*").Kind);
        Assert.Equal(FilterKind.AppRule, FilterDescriptions.Classify("criofire:v1|block|out|C:\\a.exe").Kind);
    }

    [Fact]
    public void NeedsSomethingToMatch()
    {
        Assert.Null(NetRule.Create(RuleAction.Block, TrafficDirection.Outbound, NetProtocol.Any, "", "*", null, out var error));
        Assert.NotNull(error);
        Assert.NotNull(NetRule.Create(RuleAction.Block, TrafficDirection.Outbound, NetProtocol.Udp, null, null, null, out _));
    }

    [Fact]
    public void MoreSpecificRulesWeighMoreAndBlockWinsTies()
    {
        var appBlock = NetRule.Create(RuleAction.Block, TrafficDirection.Outbound, NetProtocol.Any, "443", null, @"C:\a.exe", out _)!;
        var appAllow = appBlock with { Action = RuleAction.Allow };
        var portBlock = appBlock with { AppPath = null };
        var portAllow = portBlock with { Action = RuleAction.Allow };
        Assert.True(appAllow.Weight > portBlock.Weight);
        Assert.True(appBlock.Weight > appAllow.Weight);
        Assert.True(portBlock.Weight > portAllow.Weight);
        Assert.True(portAllow.Weight > 10);   // beats a plain program rule
        Assert.True(appBlock.Weight <= 15);   // FWP_UINT8 weights must stay within 0-15
    }

    [Fact]
    public void SummaryReadsNaturally()
    {
        var rule = NetRule.Create(RuleAction.Block, TrafficDirection.Inbound, NetProtocol.Tcp, "445", null, null, out _)!;
        Assert.Equal("TCP · local port 445", rule.Summary());
        var app = NetRule.Create(RuleAction.Allow, TrafficDirection.Outbound, NetProtocol.Any, "443", "203.0.113.0/24", @"C:\Apps\chat.exe", out _)!;
        Assert.Equal("port 443 · 203.0.113.0/24 · chat.exe", app.Summary());
    }

    [Fact]
    public void ListedRulesCarryTheirDetails()
    {
        var rule = NetRule.Create(RuleAction.Block, TrafficDirection.Inbound, NetProtocol.Tcp, "445", null, null, out _)!;
        var info = RuleInfo.From(new CrioFireFilter(9, "n", FilterLayers.RecvAcceptV4, null, FilterKind.NetRule, null, rule));
        Assert.Equal("block", info.Action);
        Assert.Equal("in", info.Direction);
        Assert.Equal("tcp", info.Protocol);
        Assert.Equal("445", info.Ports);
        Assert.Null(info.Addresses);
        Assert.Equal("NetRule", info.Kind);
        Assert.Equal("TCP · local port 445", info.Summary);
    }

    [Fact]
    public void RangeStructMatchesWindowsSdk() => Assert.Equal(32, Unsafe.SizeOf<FWP_RANGE0>());

    [Fact]
    public void AddNetRuleIsAWriteOperation() => Assert.True(ApiOps.IsWrite(ApiOps.AddNetRule));
}

public class NetRuleCommandTests
{
    [Fact]
    public void BlockInboundPort()
    {
        var c = CommandLine.Parse(["block", "--in", "--tcp", "--port", "445"], out var error);
        Assert.Null(error);
        Assert.Equal(CommandKind.Block, c.Kind);
        Assert.Equal("criofire:v1|net|block|in|tcp|445|*|*", c.Net!.Format());
    }

    [Fact]
    public void AllowProgramOnOnePort()
    {
        var c = CommandLine.Parse(["allow", @"C:\Apps\chat.exe", "--port", "443"], out var error);
        Assert.Null(error);
        Assert.Equal(RuleAction.Allow, c.Net!.Action);
        Assert.Equal(TrafficDirection.Outbound, c.Net.Direction);
        Assert.EndsWith("chat.exe", c.Net.AppPath);
    }

    [Fact]
    public void BlockAddressesRepeatedOptionsAddUp()
    {
        var c = CommandLine.Parse(["block", "--addr", "203.0.113.0/24", "--addr", "198.51.100.7", "--both"], out var error);
        Assert.Null(error);
        Assert.Equal("203.0.113.0/24,198.51.100.7", c.Net!.Addresses);
        Assert.Equal(TrafficDirection.Both, c.Net.Direction);
        Assert.Null(c.Net.AppPath);
    }

    [Theory]
    [InlineData("block", "--port")]
    [InlineData("block", "--port", "--in")]
    [InlineData("block", "--port", "0")]
    [InlineData("block", "--addr", "nowhere")]
    [InlineData("block", "--tcp", "--udp", "--port", "53")]
    [InlineData("allow", "--port", "443", "--for", "60")]
    [InlineData("unblock", "--port", "445")]
    public void RejectsBadNetOptions(params string[] args)
    {
        CommandLine.Parse(args, out var error);
        Assert.NotNull(error);
    }

    [Fact]
    public void PlainProgramRulesAreUnchanged()
    {
        var c = CommandLine.Parse(["block", @"C:\a.exe"], out var error);
        Assert.Null(error);
        Assert.Null(c.Net);
    }
}

public class InstallerCommandTests
{
    [Fact]
    public void SetupDefaultsToLearning()
    {
        var c = CommandLine.Parse(["setup"], out var error);
        Assert.Null(error);
        Assert.Equal(CommandKind.Setup, c.Kind);
        Assert.Equal(FirewallMode.Learning, c.Mode);
        Assert.False(c.AllowRunning);
        Assert.True(c.Yes);
    }

    [Fact]
    public void SetupTakesModeAndAllowRunning()
    {
        var c = CommandLine.Parse(["setup", "--mode", "ask", "--allow-running"], out var error);
        Assert.Null(error);
        Assert.Equal(FirewallMode.Ask, c.Mode);
        Assert.True(c.AllowRunning);
    }

    [Theory]
    [InlineData("setup", "--mode")]
    [InlineData("setup", "--mode", "loud")]
    [InlineData("setup", "--yes")]
    [InlineData("uninstall", "--everything")]
    public void RejectsBadInstallerArguments(params string[] args)
    {
        CommandLine.Parse(args, out var error);
        Assert.NotNull(error);
    }

    [Fact]
    public void UninstallCanRemoveData()
    {
        Assert.True(CommandLine.Parse(["uninstall", "--remove-data"], out _).RemoveData);
        Assert.False(CommandLine.Parse(["uninstall"], out _).RemoveData);
    }
}
