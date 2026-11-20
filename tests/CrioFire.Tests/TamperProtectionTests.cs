using CrioFire.Cli;
using CrioFire.Core;
using CrioFire.Core.Api;

namespace CrioFire.Tests;

public sealed class TamperProtectionTests : IDisposable
{
    private readonly string _path = Path.Combine(Path.GetTempPath(), $"criofire-protection-{Guid.NewGuid():N}.json");

    public void Dispose() => File.Delete(_path);

    [Fact]
    public void ProtectionIsOnUntilTurnedOff()
    {
        var protection = new TamperProtection(_path);
        Assert.True(protection.RequireAdmin);   // nothing saved yet: on

        protection.SetRequireAdmin(false);
        Assert.False(new TamperProtection(_path).RequireAdmin);

        protection.SetRequireAdmin(true);
        Assert.True(protection.RequireAdmin);
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

    private static string? CodeOfAChange(ApiHandler handler, uint? session) =>
        handler.Handle(new ApiRequest { Op = ApiOps.SetUpdateCheck, Enabled = true }, ClientRights.CrioFireApp, session).Code;

    [Fact]
    public void OneApprovalCanLetTheAppChangeRulesForAWhile()
    {
        var handler = new ApiHandler(null!, protection: new TamperProtection(_path));
        Assert.Equal(ApiOps.ApprovalRequired, CodeOfAChange(handler, 3));

        // The app cannot unlock itself, and neither can another program.
        Assert.Equal(ApiOps.ApprovalRequired, handler.Handle(new ApiRequest { Op = ApiOps.Unlock }, ClientRights.CrioFireApp, 3).Code);
        Assert.False(handler.Handle(new ApiRequest { Op = ApiOps.Unlock }, ClientRights.ReadOnly, 3).Ok);
        Assert.Equal(ApiOps.ApprovalRequired, CodeOfAChange(handler, 3));

        // An approved (elevated) request from the same Windows session does.
        var unlocked = handler.Handle(new ApiRequest { Op = ApiOps.Unlock }, ClientRights.Administrator, 3);
        Assert.True(unlocked.Ok);
        Assert.InRange(unlocked.UnlockedUntilUtc!.Value, DateTime.UtcNow.AddMinutes(9), DateTime.UtcNow.AddMinutes(11));
        Assert.Null(CodeOfAChange(handler, 3));                                // no longer asks for approval
        Assert.Equal(ApiOps.ApprovalRequired, CodeOfAChange(handler, 4));      // another person's session still does
        Assert.Equal(ApiOps.ApprovalRequired, CodeOfAChange(handler, null));

        // Tamper protection itself always needs approval.
        Assert.Equal(ApiOps.ApprovalRequired, handler.Handle(new ApiRequest { Op = ApiOps.SetProtection, Enabled = false }, ClientRights.CrioFireApp, 3).Code);

        // The app can ask again at any time; another program cannot end it for the app.
        Assert.False(handler.Handle(new ApiRequest { Op = ApiOps.Lock }, ClientRights.ReadOnly, 3).Ok);
        Assert.Null(CodeOfAChange(handler, 3));
        Assert.True(handler.Handle(new ApiRequest { Op = ApiOps.Lock }, ClientRights.CrioFireApp, 3).Ok);
        Assert.Equal(ApiOps.ApprovalRequired, CodeOfAChange(handler, 3));
    }

    [Fact]
    public void AnUnlockIsShortAndEndsWithTheSetting()
    {
        var handler = new ApiHandler(null!, protection: new TamperProtection(_path));

        // Never longer than an hour, whatever is asked.
        var long1 = handler.Handle(new ApiRequest { Op = ApiOps.Unlock, ExpiresMinutes = 100_000 }, ClientRights.Administrator, 3);
        Assert.InRange(long1.UnlockedUntilUtc!.Value, DateTime.UtcNow.AddMinutes(59), DateTime.UtcNow.AddMinutes(61));

        // Not without a session (the command line working on its own, without the service).
        Assert.False(handler.Handle(new ApiRequest { Op = ApiOps.Unlock }, ClientRights.Administrator).Ok);

        // Turning protection on again (or off) ends whatever was allowed for a while.
        Assert.True(handler.Handle(new ApiRequest { Op = ApiOps.SetProtection, Enabled = true }, ClientRights.Administrator, 3).Ok);
        Assert.Equal(ApiOps.ApprovalRequired, CodeOfAChange(handler, 3));

        // With protection off there is nothing to unlock.
        handler.Handle(new ApiRequest { Op = ApiOps.SetProtection, Enabled = false }, ClientRights.Administrator, 3);
        Assert.False(handler.Handle(new ApiRequest { Op = ApiOps.Unlock }, ClientRights.Administrator, 3).Ok);

        Assert.Contains("10 minutes", ApprovalText.Describe(new ApiRequest { Op = ApiOps.Unlock }), StringComparison.Ordinal);
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
