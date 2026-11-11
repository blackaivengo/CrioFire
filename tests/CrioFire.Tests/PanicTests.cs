using CrioFire.Cli;
using CrioFire.Core;

namespace CrioFire.Tests;

/// <summary>The panic switch: allow everything or block everything while keeping the rules, or remove them.</summary>
public class PanicTests
{
    [Theory]
    [InlineData("panic", "allow")]                // the safe default keeps every rule
    [InlineData("panic allow", "allow")]
    [InlineData("panic BLOCK", "block")]
    [InlineData("panic off", "off")]
    [InlineData("panic resume", "off")]
    [InlineData("resume", "off")]
    [InlineData("panic remove", "remove")]
    public void PanicActionsFromTheCommandLine(string line, string expected)
    {
        var command = CommandLine.Parse(line.Split(' '), out var error);
        Assert.Null(error);
        Assert.Equal(CommandKind.Panic, command.Kind);
        Assert.Equal(expected, command.PanicAction);
    }

    [Theory]
    [InlineData("panic now")]
    [InlineData("panic allow block")]
    [InlineData("resume all")]
    public void BadPanicCommandsAreRefused(string line)
    {
        CommandLine.Parse(line.Split(' '), out var error);
        Assert.NotNull(error);
    }

    [Theory]
    [InlineData(PanicState.AllowAll, "criofire:v1|panic|allow")]
    [InlineData(PanicState.BlockAll, "criofire:v1|panic|block")]
    public void PanicFiltersAreRecognized(PanicState state, string description)
    {
        Assert.Equal(description, FilterDescriptions.Panic(state));
        Assert.Equal(FilterKind.Panic, FilterDescriptions.Classify(description).Kind);
        Assert.Equal(state, FilterDescriptions.PanicOf(description));
        Assert.False(RuleDescription.TryParse(description, out _));
    }

    [Fact]
    public void PanicOffIsNeverAFilter()
    {
        Assert.Null(FilterDescriptions.PanicOf("criofire:v1|panic|off"));
        Assert.Equal(FilterKind.Unknown, FilterDescriptions.Classify("criofire:v1|panic|off").Kind);
    }

    [Fact]
    public void TrafficAllowedDuringPanicIsLabelledPaused()
    {
        var pause = new CrioFireFilter(1, "p", FilterLayers.ConnectV4, null, FilterKind.Panic, Panic: PanicState.AllowAll);
        var rule = new CrioFireFilter(2, "r", FilterLayers.ConnectV4, new RuleDescription(RuleAction.Allow, TrafficDirection.Outbound, @"C:\Apps\a.exe"));
        var connection = new AllowedConnection(DateTime.UtcNow, @"C:\Apps\a.exe", System.Net.Sockets.ProtocolType.Tcp, null,
            new System.Net.IPEndPoint(System.Net.IPAddress.Parse("203.0.113.1"), 443), TrafficDirection.Outbound, false, 99, null);

        var found = AllowReasons.Resolve([rule, pause], connection);
        Assert.Equal(pause, found);
        Assert.Equal(AllowReason.Paused, AllowReasons.Classify(found, false));
        Assert.Equal("Panic: rules paused", AllowReasons.Label(nameof(AllowReason.Paused), "out"));
        Assert.False(AllowReasons.IsAutomatic(AllowReason.Paused));
    }
}
