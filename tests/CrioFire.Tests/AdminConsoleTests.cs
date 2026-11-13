using CrioFire.Core;
using CrioFire.Core.Management;
using CrioFire.Server;

namespace CrioFire.Tests;

/// <summary>The admin console's accounts and how it judges each PC's state.</summary>
public sealed class AdminConsoleTests : IDisposable
{
    private static readonly DateTime Now = new(2026, 11, 13, 2, 0, 0, DateTimeKind.Utc);
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "criofire-admin-" + Guid.NewGuid().ToString("N"));

    public void Dispose()
    {
        if (Directory.Exists(_dir))
        {
            Directory.Delete(_dir, recursive: true);
        }
    }

    [Fact]
    public void AdministratorsSignInWithTheirPasswordOnly()
    {
        var admins = new AdminAccounts(_dir);
        Assert.False(admins.Any());

        admins.Add("Dana", "correct horse battery", Now);

        Assert.True(admins.Any());
        Assert.Null(admins.Verify("dana", "wrong password!", Now));
        Assert.Null(admins.Verify("nobody", "correct horse battery", Now));
        Assert.Null(admins.Verify(null, null, Now));
        var signedIn = admins.Verify("DANA", "correct horse battery", Now.AddHours(1));
        Assert.NotNull(signedIn);
        Assert.Equal("Dana", signedIn.Name);
        Assert.Equal(Now.AddHours(1), Assert.Single(new AdminAccounts(_dir).List()).LastSignInUtc);
    }

    [Fact]
    public void PasswordsAreStoredSaltedAndHashed()
    {
        var admins = new AdminAccounts(_dir);
        admins.Add("dana", "correct horse battery", Now);
        admins.Add("sam", "correct horse battery", Now);

        var text = File.ReadAllText(Directory.GetFiles(_dir, "*.json", SearchOption.AllDirectories).Single());
        Assert.DoesNotContain("correct horse battery", text, StringComparison.Ordinal);
        var list = admins.List();
        Assert.NotEqual(list[0].Hash, list[1].Hash);   // same password, different salts
        Assert.True(list[0].Iterations >= 100_000);
    }

    [Fact]
    public void WeakPasswordsBadNamesAndDuplicatesAreRefused()
    {
        var admins = new AdminAccounts(_dir);
        admins.Add("dana", "correct horse battery", Now);

        Assert.Throws<ArgumentException>(() => admins.Add("sam", "short", Now));
        Assert.Throws<ArgumentException>(() => admins.Add("sam smith", "correct horse battery", Now));
        Assert.Throws<ArgumentException>(() => admins.Add("<script>", "correct horse battery", Now));
        Assert.Throws<ArgumentException>(() => admins.Add("DANA", "correct horse battery", Now));
        Assert.Single(admins.List());
    }

    [Fact]
    public void PasswordsChangeAndTheLastAdministratorStays()
    {
        var admins = new AdminAccounts(_dir);
        admins.Add("dana", "correct horse battery", Now);
        admins.Add("sam", "another long password", Now);

        admins.SetPassword("dana", "a brand new password");
        Assert.Null(admins.Verify("dana", "correct horse battery", Now));
        Assert.NotNull(admins.Verify("dana", "a brand new password", Now));

        admins.Remove("sam");
        Assert.Throws<ArgumentException>(() => admins.Remove("dana"));
        Assert.Throws<ArgumentException>(() => admins.Remove("sam"));
        Assert.Equal("dana", Assert.Single(admins.List()).Name);
    }

    [Fact]
    public void EachPcIsJudgedOkNeedingAttentionOfflineOrNew()
    {
        var store = new ServerStore(_dir);
        var settings = new ServerSettings(CheckinSeconds: 300);
        var (token, _) = store.CreateToken(TimeSpan.FromDays(7), uses: 10, null, Now);
        string Enroll(string name) => store.Enroll(new EnrollRequest(token, name, null, null), "fw01", "10.0.0.5", Now, out _)!.DeviceId;
        var fine = Enroll("FINE");
        var panicking = Enroll("PANIC");
        var quiet = Enroll("QUIET");
        var fresh = Enroll("FRESH");
        var waiting = Enroll("WAITING");
        var policy = store.CreatePolicy("Office", new RuleSet(), "ask", allowUserRules: true, requireAdmin: false, Now);
        store.Assign(waiting, policy.Id);

        CheckinReport Report(string name) => new() { Computer = name, Installed = true, License = "business" };
        store.RecordCheckin(fine, Report("FINE"), "10.0.0.1", Now);
        store.RecordCheckin(panicking, Report("PANIC") with { Panic = "block", ChangedPrograms = 2 }, "10.0.0.2", Now);
        store.RecordCheckin(quiet, Report("QUIET"), "10.0.0.3", Now.AddMinutes(-20));
        store.RecordCheckin(waiting, Report("WAITING"), "10.0.0.4", Now);

        var views = AdminApi.Devices(store, settings, Now).ToDictionary(v => v.Computer);

        Assert.Equal("ok", views["FINE"].Status);
        Assert.Empty(views["FINE"].Problems);
        Assert.True(views["FINE"].PolicyApplied);
        Assert.Equal("attention", views["PANIC"].Status);
        Assert.Equal(2, views["PANIC"].Problems.Count);
        Assert.Equal("offline", views["QUIET"].Status);
        Assert.Equal("new", views["FRESH"].Status);
        Assert.Equal("attention", views["WAITING"].Status);
        Assert.Equal("Office", views["WAITING"].PolicyName);
        Assert.False(views["WAITING"].PolicyApplied);

        // Once the PC reports the policy's version, it is fine.
        store.RecordCheckin(waiting, Report("WAITING") with { PolicyId = policy.Id, PolicyVersion = policy.Version }, "10.0.0.4", Now);
        var after = AdminApi.Devices(store, settings, Now).Single(v => v.Computer == "WAITING");
        Assert.Equal("ok", after.Status);
        Assert.True(after.PolicyApplied);
    }

    [Fact]
    public void TheConsoleNeverShowsEnrollmentCodeHashes()
    {
        var store = new ServerStore(_dir);
        var (_, record) = store.CreateToken(TimeSpan.FromDays(7), uses: 3, "sales", Now);

        var view = TokenView.Of(record);

        Assert.Equal(record.Id, view.Id);
        Assert.Equal(3, view.UsesLeft);
        Assert.DoesNotContain(typeof(TokenView).GetProperties(), p => p.Name.Contains("Hash", StringComparison.Ordinal));
    }
}
