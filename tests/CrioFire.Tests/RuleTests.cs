using CrioFire.Core;

namespace CrioFire.Tests;

public class RuleDescriptionTests
{
    [Theory]
    [InlineData(RuleAction.Block, TrafficDirection.Outbound, @"C:\Program Files\App\app.exe", @"criofire:v1|block|out|C:\Program Files\App\app.exe")]
    [InlineData(RuleAction.Allow, TrafficDirection.Inbound, @"C:\a.exe", @"criofire:v1|allow|in|C:\a.exe")]
    [InlineData(RuleAction.Block, TrafficDirection.Both, @"D:\x|y.exe", @"criofire:v1|block|both|D:\x|y.exe")]
    public void FormatAndParseRoundTrip(RuleAction action, TrafficDirection direction, string path, string expected)
    {
        var rule = new RuleDescription(action, direction, path);

        Assert.Equal(expected, rule.Format());
        Assert.True(RuleDescription.TryParse(expected, out var parsed));
        Assert.Equal(rule, parsed);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("something else")]
    [InlineData("criofire:v2|block|out|C:\\a.exe")]
    [InlineData("criofire:v1|drop|out|C:\\a.exe")]
    [InlineData("criofire:v1|block|sideways|C:\\a.exe")]
    [InlineData("criofire:v1|block|out|")]
    [InlineData("criofire:v1|block|out")]
    public void ParseRejectsForeignOrBrokenText(string? text)
    {
        Assert.False(RuleDescription.TryParse(text, out var parsed));
        Assert.Null(parsed);
    }
}

public class FilterLayerTests
{
    [Fact]
    public void OutboundUsesBothConnectLayers()
    {
        var layers = FilterLayers.For(TrafficDirection.Outbound);
        Assert.Equal(new[] { WfpIds.LayerAleAuthConnectV4, WfpIds.LayerAleAuthConnectV6 }, layers.Select(l => l.Key));
    }

    [Fact]
    public void InboundUsesBothRecvAcceptLayers()
    {
        var layers = FilterLayers.For(TrafficDirection.Inbound);
        Assert.Equal(new[] { WfpIds.LayerAleAuthRecvAcceptV4, WfpIds.LayerAleAuthRecvAcceptV6 }, layers.Select(l => l.Key));
    }

    [Fact]
    public void BothUsesAllFourLayers() => Assert.Equal(4, FilterLayers.For(TrafficDirection.Both).Count);

    [Theory]
    [InlineData(0)]
    [InlineData(4)]
    public void InvalidDirectionThrows(int value) =>
        Assert.Throws<ArgumentOutOfRangeException>(() => FilterLayers.For((TrafficDirection)value));

    [Fact]
    public void CrioFireKeysAreDistinctFromWindowsKeys()
    {
        var all = new[] { WfpIds.ProviderKey, WfpIds.SubLayerKey }.Concat(FilterLayers.All.Select(l => l.Key)).Append(WfpIds.ConditionAleAppId);
        Assert.Equal(all.Count(), all.Distinct().Count());
    }
}
