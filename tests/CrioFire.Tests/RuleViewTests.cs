using CrioFire.Core;
using CrioFire.Core.Api;

namespace CrioFire.Tests;

/// <summary>The Rules page's filter, "what is blocked" summary and allow/block switch.</summary>
public class RuleViewTests
{
    private static readonly RuleInfo AppAllow = new(1, "AppRule", "allow", "out", @"C:\Apps\chat.exe", "outbound IPv4", "a");
    private static readonly RuleInfo AppBlockIn = new(2, "AppRule", "block", "in", @"C:\Apps\game.exe", "inbound IPv4", "b");
    private static readonly RuleInfo NetSmb = new(3, "NetRule", "block", "in", null, "inbound IPv4", "c", Protocol: "tcp", Ports: "445,8000-8100", Summary: "TCP · local port 445,8000-8100");
    private static readonly RuleInfo NetRange = new(4, "NetRule", "block", "both", @"C:\Apps\chat.exe", "outbound IPv4", "d", Addresses: "203.0.113.0/24", Summary: "203.0.113.0/24");
    private static readonly RuleInfo NetAllow = new(5, "NetRule", "allow", "out", null, "outbound IPv4", "e", Protocol: "udp", Ports: "53", Summary: "UDP · port 53");
    private static readonly RuleInfo Service = new(6, "ServiceRule", "block", "out", null, "outbound IPv4", "f", Service: "DiagTrack");

    [Theory]
    [InlineData(1, null, "allow", null, true)]
    [InlineData(1, null, "block", null, false)]
    [InlineData(2, null, null, "in", true)]
    [InlineData(2, null, null, "out", false)]
    [InlineData(4, null, null, "out", true)]        // a "both" rule matches either direction
    [InlineData(1, "chat", null, null, true)]
    [InlineData(1, "CHAT.EXE apps", null, null, true)]
    [InlineData(1, "chat game", null, null, false)]  // every word must match
    [InlineData(3, "445", null, null, true)]
    [InlineData(3, "8050", null, null, true)]        // inside the range 8000-8100
    [InlineData(3, ":8050", null, null, true)]
    [InlineData(3, "9000", null, null, false)]
    [InlineData(4, "203.0.113.77", null, null, true)] // inside the /24
    [InlineData(4, "198.51.100.1", null, null, false)]
    [InlineData(6, "diagtrack", null, null, true)]
    public void RulesAreFiltered(int id, string? search, string? action, string? direction, bool expected)
    {
        var rule = new[] { AppAllow, AppBlockIn, NetSmb, NetRange, NetAllow, Service }.Single(r => r.FilterId == (ulong)id);
        Assert.Equal(expected, RuleViews.Matches(rule, search, action, direction));
    }

    [Fact]
    public void BlockedPortsAndAddressesAreListed()
    {
        var blocked = RuleViews.Blocked([AppAllow, NetSmb, NetRange, NetAllow, Service]);
        Assert.Equal(3, blocked.Count);   // 445, 8000-8100, 203.0.113.0/24 (allow rules are not listed)
        Assert.Contains(blocked, b => b.Kind == "port" && b.Value == "445" && b.Label == "TCP 445 · SMB (file sharing) · inbound · any program");
        Assert.Contains(blocked, b => b.Kind == "port" && b.Value == "8000-8100" && b.Label.StartsWith("TCP 8000-8100 · inbound", StringComparison.Ordinal));
        Assert.Contains(blocked, b => b.Kind == "address" && b.Label == "203.0.113.0/24 · in and out · chat.exe");
    }

    [Fact]
    public void NetworkRulesCanBeSwitched()
    {
        var allowed = RuleViews.Changed(NetSmb, action: "allow")!;
        Assert.Equal(RuleAction.Allow, allowed.Action);
        Assert.Equal(TrafficDirection.Inbound, allowed.Direction);
        Assert.Equal(NetProtocol.Tcp, allowed.Protocol);
        Assert.Equal("445,8000-8100", allowed.Ports);

        var both = RuleViews.Changed(NetAllow, direction: "both")!;
        Assert.Equal(RuleAction.Allow, both.Action);
        Assert.Equal(TrafficDirection.Both, both.Direction);

        Assert.Null(RuleViews.Changed(AppAllow, action: "block"));   // program rules are switched with setRule
        Assert.Equal("block", RuleViews.Opposite("allow"));
        Assert.Equal("allow", RuleViews.Opposite("block"));
    }

    [Theory]
    [InlineData(@"C:\Program Files\Vendor\App\bin\app.exe", 20, @"C:\Program Files\|Vendor\App\bin\|app.exe")]
    [InlineData(@"C:\Apps\app.exe", 40, @"C:\Apps\app.exe")]
    [InlineData(@"C:\averyveryveryverylongfoldername\x.exe", 10, @"C:\|averyveryv|eryverylon|gfoldernam|e\x.exe")]
    public void PathsWrapAtBackslashes(string path, int max, string expected)
    {
        var lines = TextWrap.Path(path, max);
        Assert.Equal(expected, string.Join("|", lines));
        Assert.Equal(path, string.Concat(lines));
    }
}
