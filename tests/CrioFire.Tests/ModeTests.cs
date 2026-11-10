using CrioFire.Cli;
using CrioFire.Core;

namespace CrioFire.Tests;

public class FilterDescriptionTests
{
    [Theory]
    [InlineData(FirewallMode.Ask, "criofire:v1|default|ask")]
    [InlineData(FirewallMode.AllowList, "criofire:v1|default|allowlist")]
    public void DefaultBlockRoundTrips(FirewallMode mode, string text)
    {
        Assert.Equal(text, FilterDescriptions.DefaultBlock(mode));
        Assert.Equal((FilterKind.DefaultBlock, (FirewallMode?)mode), FilterDescriptions.Classify(text));
    }

    [Theory]
    [InlineData("criofire:v1|builtin|svchost", FilterKind.BuiltInAllow)]
    [InlineData(@"criofire:v1|allow|out|C:\a.exe", FilterKind.AppRule)]
    [InlineData("criofire:v1|default|learning", FilterKind.Unknown)]
    [InlineData("criofire:v1|default|sometimes", FilterKind.Unknown)]
    [InlineData("criofire:v1|builtin|", FilterKind.Unknown)]
    [InlineData("something else", FilterKind.Unknown)]
    [InlineData(null, FilterKind.Unknown)]
    public void ClassifyRecognisesEachKind(string? text, FilterKind expected) =>
        Assert.Equal(expected, FilterDescriptions.Classify(text).Kind);

    [Theory]
    [InlineData("learning", FirewallMode.Learning)]
    [InlineData("ASK", FirewallMode.Ask)]
    [InlineData("allow-list", FirewallMode.AllowList)]
    public void ModesParse(string text, FirewallMode expected)
    {
        Assert.True(FilterDescriptions.TryParseMode(text, out var mode));
        Assert.Equal(expected, mode);
        Assert.False(FilterDescriptions.TryParseMode("sometimes", out _));
    }
}

public class ModeCommandTests
{
    [Fact]
    public void ModeWithoutArgumentsShowsTheMode() =>
        Assert.Equal(CommandKind.ModeShow, CommandLine.Parse(["mode"], out _).Kind);

    [Fact]
    public void ModeSetParsesOptions()
    {
        var c = CommandLine.Parse(["mode", "allowlist", "--allow-running", "--yes"], out var error);
        Assert.Null(error);
        Assert.Equal(new Command(CommandKind.ModeSet, Mode: FirewallMode.AllowList, Yes: true, AllowRunning: true), c);
    }

    [Theory]
    [InlineData("mode", "sometimes")]
    [InlineData("mode", "ask", "--force")]
    public void BadModeInputGivesAnError(params string[] args)
    {
        var c = CommandLine.Parse(args, out var error);
        Assert.NotNull(error);
        Assert.Equal(CommandKind.Help, c.Kind);
    }

    [Fact]
    public void AllowDefaultsToOutbound()
    {
        var c = CommandLine.Parse(["allow", @"C:\a.exe"], out var error);
        Assert.Null(error);
        Assert.Equal(new Command(CommandKind.Allow, @"C:\a.exe", TrafficDirection.Outbound), c);
    }
}
