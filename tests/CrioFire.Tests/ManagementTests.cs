using System.Security.Cryptography.X509Certificates;
using CrioFire.Cli;
using CrioFire.Core;
using CrioFire.Core.Management;
using CrioFire.Server;

namespace CrioFire.Tests;

public sealed class ManagementTests : IDisposable
{
    private static readonly DateTime Now = new(2026, 11, 13, 2, 0, 0, DateTimeKind.Utc);
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "criofire-server-" + Guid.NewGuid().ToString("N"));

    public void Dispose()
    {
        if (Directory.Exists(_dir))
        {
            Directory.Delete(_dir, recursive: true);
        }
    }

    [Fact]
    public void APcEnrollsWithATokenAndThenAuthenticatesWithItsSecret()
    {
        var store = new ServerStore(_dir);
        var (token, record) = store.CreateToken(TimeSpan.FromDays(7), uses: 2, "office", Now);

        var enrolled = store.Enroll(new EnrollRequest(token, "PC-1", "Windows 11", "0.1"), "fw01", "10.0.0.5", Now, out var error);

        Assert.Null(error);
        Assert.NotNull(enrolled);
        Assert.StartsWith(ServerStore.TokenPrefix, token, StringComparison.Ordinal);
        Assert.Equal("fw01", enrolled.ServerName);
        Assert.Equal(1, Assert.Single(store.Tokens()).UsesLeft);
        Assert.Equal(record.Id, store.Tokens()[0].Id);
        var device = store.Authenticate($"Device {enrolled.DeviceId}.{enrolled.Secret}");
        Assert.NotNull(device);
        Assert.Equal("PC-1", device.Computer);
        Assert.Null(store.Authenticate($"Device {enrolled.DeviceId}.wrong"));
        Assert.Null(store.Authenticate($"Bearer {enrolled.DeviceId}.{enrolled.Secret}"));
        Assert.Null(store.Authenticate(null));
    }

    [Fact]
    public void TokensRunOutAndExpire()
    {
        var store = new ServerStore(_dir);
        var (once, _) = store.CreateToken(TimeSpan.FromDays(1), uses: 1, null, Now);
        var (old, _) = store.CreateToken(TimeSpan.FromHours(1), uses: 5, null, Now);

        Assert.NotNull(store.Enroll(new EnrollRequest(once, "PC-1", null, null), "s", null, Now, out _));
        Assert.Null(store.Enroll(new EnrollRequest(once, "PC-2", null, null), "s", null, Now, out var used));
        Assert.Null(store.Enroll(new EnrollRequest(old, "PC-3", null, null), "s", null, Now.AddHours(2), out var expired));
        Assert.Null(store.Enroll(new EnrollRequest("cfe_guess", "PC-4", null, null), "s", null, Now, out var wrong));

        Assert.Contains("not valid", used, StringComparison.Ordinal);
        Assert.Contains("expired", expired, StringComparison.Ordinal);
        Assert.Contains("not valid", wrong, StringComparison.Ordinal);
    }

    [Fact]
    public void ReEnrollingReplacesThePcsOldEntry()
    {
        var store = new ServerStore(_dir);
        var (token, _) = store.CreateToken(TimeSpan.FromDays(1), uses: 2, null, Now);
        var first = store.Enroll(new EnrollRequest(token, "PC-1", null, null), "s", null, Now, out _)!;
        var second = store.Enroll(new EnrollRequest(token, "pc-1", null, null), "s", null, Now, out _)!;

        Assert.Equal(second.DeviceId, Assert.Single(store.Devices()).DeviceId);
        Assert.Null(store.Authenticate($"Device {first.DeviceId}.{first.Secret}"));
    }

    [Fact]
    public void CheckinsAreKeptAndSurviveARestart()
    {
        var store = new ServerStore(_dir);
        var (token, _) = store.CreateToken(TimeSpan.FromDays(1), uses: 1, null, Now);
        var enrolled = store.Enroll(new EnrollRequest(token, "PC-1", null, null), "s", null, Now, out _)!;

        store.RecordCheckin(enrolled.DeviceId, new CheckinReport { Computer = "PC-1", Mode = "ask", ProgramRules = 7 }, "10.0.0.9", Now.AddMinutes(1));
        store.SaveIfChanged();
        var reloaded = new ServerStore(_dir);

        var device = Assert.Single(reloaded.Devices());
        Assert.Equal(Now.AddMinutes(1), device.LastSeenUtc);
        Assert.Equal("10.0.0.9", device.Address);
        Assert.Equal(7, device.LastReport!.ProgramRules);
        Assert.NotNull(reloaded.Authenticate($"Device {enrolled.DeviceId}.{enrolled.Secret}"));
        Assert.True(reloaded.RemoveDevice(enrolled.DeviceId));
        Assert.Empty(new ServerStore(_dir).Devices());
    }

    [Fact]
    public void SecretsAndTokensAreNeverStoredInTheClear()
    {
        var store = new ServerStore(_dir);
        var (token, _) = store.CreateToken(TimeSpan.FromDays(1), uses: 2, null, Now);
        var enrolled = store.Enroll(new EnrollRequest(token, "PC-1", null, null), "s", null, Now, out _)!;

        var everything = string.Concat(Directory.EnumerateFiles(_dir, "*", SearchOption.AllDirectories).Select(File.ReadAllText));
        Assert.DoesNotContain(token, everything, StringComparison.Ordinal);
        Assert.DoesNotContain(enrolled.Secret, everything, StringComparison.Ordinal);
    }

    [Fact]
    public void TokensCanBeRevoked()
    {
        var store = new ServerStore(_dir);
        var (token, record) = store.CreateToken(TimeSpan.FromDays(1), uses: 3, null, Now);

        Assert.True(store.RevokeToken(record.Id));
        Assert.False(store.RevokeToken(record.Id));
        Assert.False(store.RevokeToken(@"..\devices"));
        Assert.Null(store.Enroll(new EnrollRequest(token, "PC-1", null, null), "s", null, Now, out _));
    }

    [Fact]
    public void ServerAddressesGetHttpsAndTheDefaultPort()
    {
        Assert.Equal("https://fw01:7443/", ManagementClient.NormalizeUrl("fw01"));
        Assert.Equal("https://fw01.contoso.local:9000/", ManagementClient.NormalizeUrl("fw01.contoso.local:9000"));
        Assert.Equal("https://fw01:443/", ManagementClient.NormalizeUrl("https://fw01:443/"));
        Assert.Throws<ArgumentException>(() => ManagementClient.NormalizeUrl("http://fw01"));
    }

    [Fact]
    public void TheServerCertificateCarriesItsNamesAndAStableFingerprint()
    {
        var pfx = ServerCertificate.CreateSelfSigned(["fw01", "fw01.contoso.local", "localhost"], Now);
        using var certificate = X509CertificateLoader.LoadPkcs12(pfx, null);

        var fingerprint = Fingerprints.Of(certificate);

        Assert.True(certificate.HasPrivateKey);
        Assert.Equal(95, fingerprint.Length);   // 32 bytes as "AB:" pairs
        Assert.True(Fingerprints.Matches(fingerprint, fingerprint.Replace(":", "", StringComparison.Ordinal).ToLowerInvariant()));
        Assert.False(Fingerprints.Matches(fingerprint, "00:11"));
        Assert.Contains("fw01.contoso.local", certificate.Extensions["2.5.29.17"]!.Format(false), StringComparison.Ordinal);
    }

    [Fact]
    public void ConnectionsAreSentOnlyWhenAnAdministratorAsks()
    {
        var store = new ServerStore(_dir);
        var (token, _) = store.CreateToken(TimeSpan.FromDays(1), uses: 1, null, Now);
        var pc = store.Enroll(new EnrollRequest(token, "PC-1", null, null), "s", null, Now, out _)!;
        var page = new TrafficPage(1, 3, 0, [new TrafficItem(false, Now, Now, @"C:\a.exe", null, "TCP", "out", "203.0.113.5", 443, null, "DefaultBlock", 1, 3)]);

        Assert.Null(store.PendingActivity(pc.DeviceId));
        Assert.False(store.StoreActivity(pc.DeviceId, new ActivityUpload("act_none", Now, page), Now));   // nobody asked

        var asked = store.RequestActivity(pc.DeviceId, "all", hours: 9999, limit: 9999, Now);
        Assert.Equal(720, asked.Hours);
        Assert.Equal(500, asked.Limit);
        Assert.Equal(asked, store.PendingActivity(pc.DeviceId));
        Assert.False(store.StoreActivity(pc.DeviceId, new ActivityUpload("act_other", Now, page), Now));
        Assert.True(store.StoreActivity(pc.DeviceId, new ActivityUpload(asked.RequestId, Now, page), Now));

        Assert.Null(store.PendingActivity(pc.DeviceId));
        Assert.Equal(3, Assert.Single(store.Activity(pc.DeviceId)!.Page.Items).Count);
        Assert.Throws<ArgumentException>(() => store.RequestActivity(pc.DeviceId, "everything", 1, 1, Now));
        Assert.Equal(pc.DeviceId, store.Find("pc-1")!.DeviceId);
    }

    [Fact]
    public void ThePcAnswersFromItsOwnLogs()
    {
        var blockedLog = new TrafficLog(Path.Combine(_dir, "blocked.log"));
        Directory.CreateDirectory(_dir);
        var recent = DateTime.UtcNow.AddMinutes(-5);
        blockedLog.Append(Enumerable.Range(0, 5).Select(_ => new BlockedConnection(recent, @"C:\a.exe", System.Net.Sockets.ProtocolType.Tcp, null,
            new System.Net.IPEndPoint(System.Net.IPAddress.Parse("203.0.113.5"), 443), 1, null)));

        var upload = CheckinReports.Activity(new ActivityRequest("act_1", "blocked", 1, 100, DateTime.UtcNow), blockedLog, null, DateTime.UtcNow);

        Assert.Equal("act_1", upload.RequestId);
        var row = Assert.Single(upload.Page.Items);
        Assert.Equal(@"C:\a.exe", row.App);
        Assert.Equal(5, row.Count);
    }

    [Fact]
    public void EnrollParses()
    {
        var enroll = CommandLine.Parse(["enroll", "fw01:7443", "cfe_abc", "--fingerprint", "AB:CD"], out var e1);
        Assert.Null(e1);
        Assert.Equal(CommandKind.Enroll, enroll.Kind);
        Assert.Equal("fw01:7443", enroll.Server);
        Assert.Equal("cfe_abc", enroll.Token);
        Assert.Equal("AB:CD", enroll.Fingerprint);
        Assert.Equal(CommandKind.Unenroll, CommandLine.Parse(["unenroll"], out _).Kind);
        Assert.Equal(CommandKind.Server, CommandLine.Parse(["server"], out _).Kind);
        CommandLine.Parse(["enroll", "fw01"], out var e2);
        Assert.NotNull(e2);
    }
}
