using CrioFire.Cli;
using CrioFire.Core;
using CrioFire.Core.Api;

namespace CrioFire.Tests;

public sealed class TamperProtectionTests : IDisposable
{
    private readonly string _path = Path.Combine(Path.GetTempPath(), $"criofire-protection-{Guid.NewGuid():N}.json");

    public void Dispose() => File.Delete(_path);

    [Fact]
    public void ProtectionIsOffUntilTurnedOn()
    {
        var protection = new TamperProtection(_path);
        Assert.False(protection.RequireAdmin);

        protection.SetRequireAdmin(true);
        Assert.True(new TamperProtection(_path).RequireAdmin);

        protection.SetRequireAdmin(false);
        Assert.False(protection.RequireAdmin);
    }

    [Fact]
    public void ADamagedSettingsFileCountsAsOn()
    {
        File.WriteAllText(_path, "{ broken");
        Assert.True(new TamperProtection(_path).RequireAdmin);
    }

    [Fact]
    public void WithProtectionTheAppNeedsApprovalToChangeRules()
    {
        var protection = new TamperProtection(_path);
        protection.SetRequireAdmin(true);
        var handler = new ApiHandler(null!, protection: protection);

        var response = handler.Handle(new ApiRequest { Op = ApiOps.SetRule, App = @"C:\a.exe", Action = "allow" }, ClientRights.CrioFireApp);

        Assert.False(response.Ok);
        Assert.Equal(ApiOps.ApprovalRequired, response.Code);
    }

    [Fact]
    public void ChangingProtectionAlwaysNeedsAnAdministrator()
    {
        var handler = new ApiHandler(null!, protection: new TamperProtection(_path));

        var fromApp = handler.Handle(new ApiRequest { Op = ApiOps.SetProtection, Enabled = false }, ClientRights.CrioFireApp);
        var fromAdmin = handler.Handle(new ApiRequest { Op = ApiOps.SetProtection, Enabled = true }, ClientRights.Administrator);

        Assert.Equal(ApiOps.ApprovalRequired, fromApp.Code);
        Assert.True(fromAdmin.Ok);
        Assert.True(new TamperProtection(_path).RequireAdmin);
    }

    [Fact]
    public void OtherProgramsCannotChangeAnything()
    {
        var handler = new ApiHandler(null!, protection: new TamperProtection(_path));

        var response = handler.Handle(new ApiRequest { Op = ApiOps.SetProtection, Enabled = false }, ClientRights.ReadOnly);

        Assert.False(response.Ok);
        Assert.Null(response.Code);
        Assert.True(ApiOps.IsWrite(ApiOps.SetProtection));
    }

    [Fact]
    public void RightsFollowElevationAndInstallFolder()
    {
        Assert.Equal(ClientRights.Administrator, ApiAuthorization.Rights(true, null, @"C:\Program Files\CrioFire"));
        Assert.Equal(ClientRights.CrioFireApp, ApiAuthorization.Rights(false, @"C:\Program Files\CrioFire\criofire-ui.exe", @"C:\Program Files\CrioFire"));
        Assert.Equal(ClientRights.ReadOnly, ApiAuthorization.Rights(false, @"C:\Users\x\criofire.exe", @"C:\Program Files\CrioFire"));
    }

    [Fact]
    public void ProtectionAndRequestParse()
    {
        Assert.Equal(CommandKind.Protection, CommandLine.Parse(["protection"], out _).Kind);
        var on = CommandLine.Parse(["protection", "on"], out var e1);
        Assert.Null(e1);
        Assert.True(on.All && on.Enabled);
        var request = CommandLine.Parse(["request", "e30=", @"C:\Temp\r.json"], out var e2);
        Assert.Null(e2);
        Assert.Equal(CommandKind.Request, request.Kind);
        CommandLine.Parse(["protection", "maybe"], out var e3);
        Assert.NotNull(e3);
    }
}
