using CrioFire.Cli;
using CrioFire.Core;

namespace CrioFire.Tests;

public class CommandLineTests
{
    [Fact]
    public void NoArgumentsShowsHelp()
    {
        var command = CommandLine.Parse([], out var error);
        Assert.Null(error);
        Assert.Equal(CommandKind.Help, command.Kind);
    }

    [Theory]
    [InlineData("status", CommandKind.Status)]
    [InlineData("install", CommandKind.Install)]
    [InlineData("uninstall", CommandKind.Uninstall)]
    [InlineData("list", CommandKind.List)]
    [InlineData("panic", CommandKind.Panic)]
    [InlineData("PANIC", CommandKind.Panic)]
    [InlineData("resume", CommandKind.Panic)]
    [InlineData("--version", CommandKind.Version)]
    public void SimpleVerbs(string verb, CommandKind expected)
    {
        var command = CommandLine.Parse([verb], out var error);
        Assert.Null(error);
        Assert.Equal(expected, command.Kind);
    }

    [Fact]
    public void BlockDefaultsToOutbound()
    {
        var command = CommandLine.Parse(["block", @"C:\a.exe"], out var error);
        Assert.Null(error);
        Assert.Equal(new Command(CommandKind.Block, @"C:\a.exe", TrafficDirection.Outbound), command);
    }

    [Fact]
    public void UnblockDefaultsToBoth()
    {
        var command = CommandLine.Parse(["unblock", @"C:\a.exe"], out var error);
        Assert.Null(error);
        Assert.Equal(TrafficDirection.Both, command.Direction);
    }

    [Theory]
    [InlineData("--in", TrafficDirection.Inbound)]
    [InlineData("--both", TrafficDirection.Both)]
    [InlineData("--OUT", TrafficDirection.Outbound)]
    public void BlockAcceptsDirectionBeforeOrAfterPath(string flag, TrafficDirection expected)
    {
        Assert.Equal(expected, CommandLine.Parse(["block", @"C:\a.exe", flag], out _).Direction);
        Assert.Equal(expected, CommandLine.Parse(["block", flag, @"C:\a.exe"], out _).Direction);
    }

    [Theory]
    [InlineData("block")]
    [InlineData("block", "--in")]
    [InlineData("block", @"C:\a.exe", @"C:\b.exe")]
    [InlineData("block", @"C:\a.exe", "--in", "--out")]
    [InlineData("block", @"C:\a.exe", "--sideways")]
    [InlineData("remove")]
    [InlineData("remove", "abc")]
    [InlineData("list", "extra")]
    [InlineData("frobnicate")]
    public void BadInputGivesAnError(params string[] args)
    {
        var command = CommandLine.Parse(args, out var error);
        Assert.NotNull(error);
        Assert.Equal(CommandKind.Help, command.Kind);
    }

    [Fact]
    public void RemoveParsesFilterId()
    {
        var command = CommandLine.Parse(["remove", "68213"], out var error);
        Assert.Null(error);
        Assert.Equal(68213UL, command.FilterId);
    }
}
