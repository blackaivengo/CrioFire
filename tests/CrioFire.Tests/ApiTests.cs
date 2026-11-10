using CrioFire.Core;
using CrioFire.Core.Api;

namespace CrioFire.Tests;

public class ApiProtocolTests
{
    [Fact]
    public void RequestRoundTripsAsOneLine()
    {
        var request = new ApiRequest { Op = ApiOps.SetMode, Mode = "allowlist", Apps = [@"C:\a.exe", @"C:\b c\d.exe"] };
        var line = ApiJson.Serialize(request);
        Assert.DoesNotContain('\n', line);
        Assert.Contains("\"op\":\"setMode\"", line);
        Assert.DoesNotContain("filterId", line);   // nulls are left out

        var back = ApiJson.DeserializeRequest(line)!;
        Assert.Equal(request.Op, back.Op);
        Assert.Equal(request.Mode, back.Mode);
        Assert.Equal(request.Apps, back.Apps);
    }

    [Fact]
    public void ResponseRoundTrips()
    {
        var response = new ApiResponse
        {
            Ok = true,
            Status = new StatusInfo(true, "ask", 6, "0.1.0"),
            Rules = [new RuleInfo(42, "AppRule", "block", "out", @"C:\a.exe", "outbound IPv4", "CrioFire: block a.exe")],
            Events = [new EventInfo(new DateTime(2026, 11, 9, 1, 2, 3, DateTimeKind.Utc), @"C:\a.exe", "TCP", null, "1.2.3.4:443", "out", true, 42)],
        };

        var back = ApiJson.DeserializeResponse(ApiJson.Serialize(response))!;
        Assert.True(back.Ok);
        Assert.Equal(response.Status, back.Status);
        Assert.Equal(response.Rules, back.Rules);
        Assert.Equal(response.Events, back.Events);
    }

    [Fact]
    public void RuleInfoDescribesEachKind()
    {
        var rule = new CrioFireFilter(1, "n", FilterLayers.ConnectV4, new RuleDescription(RuleAction.Allow, TrafficDirection.Both, @"C:\a.exe"));
        Assert.Equal(new RuleInfo(1, "AppRule", "allow", "both", @"C:\a.exe", "outbound IPv4", "n"), RuleInfo.From(rule));

        var catchAll = new CrioFireFilter(2, "m", FilterLayers.ConnectV6, null, FilterKind.DefaultBlock, FirewallMode.Ask);
        Assert.Equal("block", RuleInfo.From(catchAll).Action);
        Assert.Null(RuleInfo.From(catchAll).App);
    }

    [Theory]
    [InlineData(ApiOps.SetRule)]
    [InlineData(ApiOps.RemoveRules)]
    [InlineData(ApiOps.RemoveFilter)]
    [InlineData(ApiOps.SetMode)]
    [InlineData(ApiOps.Panic)]
    public void WritesAreRefusedWithoutPermission(string op)
    {
        // Refused before the engine is touched, so no engine is needed here.
        var handler = new ApiHandler(null!);
        var response = handler.Handle(new ApiRequest { Op = op }, canWrite: false);
        Assert.False(response.Ok);
        Assert.Contains("Not allowed", response.Error);
    }

    [Fact]
    public void UnknownOperationIsRefused()
    {
        var response = new ApiHandler(null!).Handle(new ApiRequest { Op = "format-c" }, canWrite: true);
        Assert.False(response.Ok);
        Assert.Contains("Unknown operation", response.Error);
    }
}

public class ApiAuthorizationTests
{
    private const string Install = @"C:\Program Files\CrioFire";

    [Theory]
    [InlineData(@"C:\Program Files\CrioFire\criofire-ui.exe", true)]
    [InlineData(@"C:\PROGRAM FILES\CRIOFIRE\CRIOFIRE.EXE", true)]
    [InlineData(@"C:\Program Files\CrioFire\criofire-svc.exe", false)]
    [InlineData(@"C:\Program Files\CrioFire\other.exe", false)]
    [InlineData(@"C:\Users\x\Downloads\criofire.exe", false)]
    [InlineData(@"C:\Program Files\CrioFire\sub\criofire.exe", false)]
    [InlineData(@"C:\Program Files\CrioFire\..\Evil\criofire.exe", false)]
    [InlineData(null, false)]
    public void OnlyCrioFireProgramsFromTheInstallFolderMayWrite(string? path, bool expected) =>
        Assert.Equal(expected, ApiAuthorization.CanWrite(clientIsElevatedAdmin: false, path, Install));

    [Fact]
    public void ElevatedAdministratorsMayAlwaysWrite() =>
        Assert.True(ApiAuthorization.CanWrite(clientIsElevatedAdmin: true, @"C:\anything\tool.exe", Install));

    [Fact]
    public void TrailingSeparatorOnTheInstallFolderDoesNotMatter() =>
        Assert.True(ApiAuthorization.CanWrite(false, @"C:\Program Files\CrioFire\criofire.exe", Install + @"\"));
}
