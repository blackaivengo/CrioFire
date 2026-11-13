using System.Net;
using System.Security.Cryptography;
using CrioFire.Core;
using CrioFire.Core.Management;
using CrioFire.Server;

namespace CrioFire.Tests;

/// <summary>The organization's license on the server: seats counted, and the key handed to PCs at check-in.</summary>
public sealed class ServerLicenseTests : IDisposable
{
    private static readonly DateTime Now = new(2026, 11, 13, 12, 0, 0, DateTimeKind.Utc);
    private readonly ECDsa _crioSoft = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly ECDsa _public;
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "criofire-serverlicense-" + Guid.NewGuid().ToString("N"));

    public ServerLicenseTests()
    {
        _public = ECDsa.Create();
        _public.ImportFromPem(_crioSoft.ExportSubjectPublicKeyInfoPem());
    }

    public void Dispose()
    {
        _crioSoft.Dispose();
        _public.Dispose();
        if (Directory.Exists(_dir))
        {
            Directory.Delete(_dir, recursive: true);
        }
    }

    [Fact]
    public void SeatsAreCountedAgainstEnrolledComputers()
    {
        var license = new ServerLicense(_dir, _public);
        license.Set(Key("CF-1", seats: 2), Now);

        var fits = license.View(2, Now);
        var over = license.View(3, Now);

        Assert.Equal(LicenseStates.Valid, fits.State);
        Assert.Equal(2, fits.Seats);
        Assert.False(fits.Over);
        Assert.True(over.Over);
        Assert.Contains("3 of 2", ServerLicense.Describe(over), StringComparison.Ordinal);
        Assert.Contains("1 more than the license covers", ServerLicense.Describe(over), StringComparison.Ordinal);
    }

    [Fact]
    public void OnlyValidKeysAreAccepted()
    {
        var license = new ServerLicense(_dir, _public);
        using var stranger = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var forged = LicenseKeys.Issue(Data("CF-X", 1000, Now.AddYears(1)), stranger);

        Assert.Throws<ArgumentException>(() => license.Set(forged, Now));
        Assert.Throws<ArgumentException>(() => license.Set("hello", Now));
        Assert.Throws<ArgumentException>(() => license.Set(LicenseKeys.Issue(Data("CF-OLD", 5, Now.AddDays(-1)), _crioSoft), Now));
        Assert.Equal(LicenseStates.None, license.Status(Now).State);

        Assert.Throws<ArgumentException>(() => new ServerLicense(_dir, publicKey: null).Set(Key("CF-1", 5), Now));
    }

    [Fact]
    public void PcsGetTheKeyOnlyWhenTheyDoNotHaveIt()
    {
        var license = new ServerLicense(_dir, _public);
        Assert.Null(license.KeyFor(null, Now));   // no license on the server

        var key = Key("CF-1", seats: 50);
        license.Set(key, Now);

        Assert.Equal(key, license.KeyFor(null, Now));
        Assert.Equal(key, license.KeyFor("CF-OTHER", Now));
        Assert.Null(license.KeyFor("CF-1", Now));
        Assert.Null(license.KeyFor(null, Now.AddYears(2)));   // expired: nothing to hand out

        license.Set(null, Now);
        Assert.Null(license.KeyFor(null, Now));
        Assert.False(File.Exists(license.FilePath));
    }

    [Fact]
    public void APcSavesTheOrganizationsLicenseOnce()
    {
        var store = new LicenseStore(Path.Combine(_dir, "pc", "license.key"));
        var key = Key("CF-1", seats: 50);

        Assert.True(CheckinReports.AcceptLicense(key, store, _public, Now));
        Assert.Equal(key, store.Key);
        Assert.False(CheckinReports.AcceptLicense(key, store, _public, Now));   // already has it

        var renewed = Key("CF-2", seats: 80);
        Assert.True(CheckinReports.AcceptLicense(renewed, store, _public, Now));
        Assert.Equal(renewed, store.Key);
    }

    [Fact]
    public void APcRefusesForgedOrExpiredKeys()
    {
        var store = new LicenseStore(Path.Combine(_dir, "pc", "license.key"));
        using var stranger = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        Assert.False(CheckinReports.AcceptLicense(LicenseKeys.Issue(Data("CF-X", 9, Now.AddYears(1)), stranger), store, _public, Now));
        Assert.False(CheckinReports.AcceptLicense(LicenseKeys.Issue(Data("CF-OLD", 9, Now.AddDays(-1)), _crioSoft), store, _public, Now));
        Assert.False(CheckinReports.AcceptLicense(null, store, _public, Now));
        Assert.Null(store.Key);
    }

    [Fact]
    public void SetupChangesThePortAndKeepsOtherSettings()
    {
        Directory.CreateDirectory(_dir);
        File.WriteAllText(Path.Combine(_dir, "settings.json"), """{ "checkinSeconds": 600, "port": 7443 }""");

        ServerSettings.SavePort(_dir, 9443);

        var settings = ServerSettings.Load(_dir);
        Assert.Equal(9443, settings.Port);
        Assert.Equal(600, settings.CheckinSeconds);
        Assert.Equal(8443, ServerSetup.ParsePort("8443"));
        Assert.Throws<ArgumentException>(() => ServerSetup.ParsePort("0"));
        Assert.Throws<ArgumentException>(() => ServerSetup.ParsePort("70000"));
        Assert.Throws<ArgumentException>(() => ServerSetup.ParsePort("-1"));
        Assert.Throws<ArgumentException>(() => ServerSetup.ParsePort("7443; del"));
    }

    [Fact]
    public void OnlyThisMachineCountsAsLocal()
    {
        Assert.True(ServerSetup.IsLocal(IPAddress.Loopback));
        Assert.True(ServerSetup.IsLocal(IPAddress.IPv6Loopback));
        Assert.True(ServerSetup.IsLocal(IPAddress.Loopback.MapToIPv6()));
        Assert.False(ServerSetup.IsLocal(IPAddress.Parse("10.0.0.5")));
        Assert.False(ServerSetup.IsLocal(null));
    }

    [Fact]
    public void OnlyTheFirstAdministratorCanBeAddedWithoutSigningIn()
    {
        var admins = new AdminAccounts(_dir);

        Assert.True(admins.AddFirst("dana", "correct horse battery", Now));
        Assert.False(admins.AddFirst("mallory", "another long password", Now));
        Assert.Equal("dana", Assert.Single(admins.List()).Name);
    }

    private string Key(string id, int seats) => LicenseKeys.Issue(Data(id, seats, Now.AddYears(1)), _crioSoft);

    private static LicenseData Data(string id, int seats, DateTime expires) =>
        new(LicenseKeys.CurrentFormat, id, "Contoso Ltd", "it@contoso.example", "business", seats, Now.AddDays(-30), expires);
}
