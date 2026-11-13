using CrioFire.Core;

namespace CrioFire.Tests;

public sealed class ProgramIdentityTests : IDisposable
{
    private static readonly DateTime Now = new(2026, 11, 12, 20, 0, 0, DateTimeKind.Utc);

    private readonly string _dir = Path.Combine(Path.GetTempPath(), "criofire-identity-" + Guid.NewGuid().ToString("N"));
    private readonly FakeSignatures _signatures = new();
    private readonly ProgramIdentityStore _store;
    private readonly IdentityGuard _guard;

    public ProgramIdentityTests()
    {
        Directory.CreateDirectory(_dir);
        _store = new ProgramIdentityStore(Path.Combine(_dir, "program-identities.json"));
        _guard = new IdentityGuard(_store, _signatures, windowsFolder: Path.Combine(_dir, "Windows"));
    }

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    [Fact]
    public void AllowingRecordsPublisherAndFingerprint()
    {
        var app = Program("chat.exe", "v1");
        _signatures.Signers[app] = "Example Corp";

        var identity = _guard.Record(app, Now);

        Assert.NotNull(identity);
        Assert.Equal("Example Corp", identity.Publisher);
        Assert.Equal(64, identity.Sha256.Length);
        Assert.Equal(identity, _store.Known(app));
    }

    [Fact]
    public void AnUntouchedProgramIsNotReported()
    {
        var app = Program("chat.exe", "v1");
        _guard.Record(app, Now);

        Assert.Empty(_guard.Review([app], Now.AddMinutes(1)));
    }

    [Fact]
    public void AnUpdateFromTheSamePublisherIsAcceptedAndRecorded()
    {
        var app = Program("chat.exe", "v1");
        _signatures.Signers[app] = "Example Corp";
        _guard.Record(app, Now);

        Rewrite(app, "v2 with more bytes");
        var finding = Assert.Single(_guard.Review([app], Now.AddMinutes(1)));

        Assert.Equal(IdentityChange.Updated, finding.Change);
        Assert.Empty(_store.Changed());
        Assert.Equal(finding.Now.Sha256, _store.Known(app)!.Sha256);
    }

    [Fact]
    public void AnotherPublisherIsAChange()
    {
        var app = Program("chat.exe", "v1");
        _signatures.Signers[app] = "Example Corp";
        _guard.Record(app, Now);

        Rewrite(app, "something else");
        _signatures.Signers[app] = "Someone Else Ltd";
        var finding = Assert.Single(_guard.Review([app], Now.AddMinutes(1)));

        Assert.Equal(IdentityChange.Changed, finding.Change);
        Assert.Equal("Example Corp", finding.Was.Publisher);
        Assert.Equal("Someone Else Ltd", finding.Now.Publisher);
    }

    [Fact]
    public void ALostSignatureIsAChange()
    {
        var app = Program("chat.exe", "v1");
        _signatures.Signers[app] = "Example Corp";
        _guard.Record(app, Now);

        Rewrite(app, "unsigned copy");
        _signatures.Signers.Remove(app);

        Assert.Equal(IdentityChange.Changed, Assert.Single(_guard.Review([app], Now.AddMinutes(1))).Change);
    }

    [Fact]
    public void NewContentsOfAnUnsignedProgramAreAChange()
    {
        var app = Program("tool.exe", "v1");
        _guard.Record(app, Now);

        Rewrite(app, "v2");

        Assert.Equal(IdentityChange.Changed, Assert.Single(_guard.Review([app], Now.AddMinutes(1))).Change);
    }

    [Fact]
    public void ATouchedFileWithTheSameContentsIsRecordedQuietly()
    {
        var app = Program("tool.exe", "v1");
        _guard.Record(app, Now);

        File.SetLastWriteTimeUtc(app, Now.AddDays(1));

        Assert.Empty(_guard.Review([app], Now.AddMinutes(1)));
        Assert.Equal(Now.AddDays(1), _store.Known(app)!.LastWriteUtc);
    }

    [Fact]
    public void AProgramSeenForTheFirstTimeIsRecordedAsItIs()
    {
        var app = Program("old-rule.exe", "v1");

        Assert.Empty(_guard.Review([app], Now));
        Assert.NotNull(_store.Known(app));
    }

    [Fact]
    public void AMissingFileIsSkipped()
    {
        var app = Program("gone.exe", "v1");
        _guard.Record(app, Now);
        File.Delete(app);

        Assert.Empty(_guard.Review([app], Now.AddMinutes(1)));
    }

    [Fact]
    public void AProgramAlreadyMarkedChangedIsNotReportedAgain()
    {
        var app = Program("tool.exe", "v1");
        _guard.Record(app, Now);
        Rewrite(app, "v2");
        var finding = Assert.Single(_guard.Review([app], Now.AddMinutes(1)));
        _store.MarkChanged(new ChangedProgram(app, null, null, finding.Was.Sha256, finding.Now.Sha256, "out", Blocked: true, Now));

        Assert.Empty(_guard.Review([app], Now.AddMinutes(2)));
    }

    [Fact]
    public void AllowingAgainClearsTheChange()
    {
        var app = Program("tool.exe", "v1");
        _store.MarkChanged(new ChangedProgram(app, null, null, "aa", "bb", "out", Blocked: true, Now));

        _guard.Record(app, Now.AddMinutes(5));

        Assert.Empty(_store.Changed());
        Assert.NotNull(_store.Known(app));
    }

    [Fact]
    public void ForgettingRemovesKnownAndChanged()
    {
        var app = Program("tool.exe", "v1");
        _guard.Record(app, Now);
        _store.MarkChanged(new ChangedProgram(app, null, null, "aa", "bb", "out", Blocked: false, Now));

        _store.Forget(app.ToUpperInvariant());

        Assert.Null(_store.Known(app));
        Assert.Empty(_store.Changed());
    }

    [Fact]
    public void TheKernelAndWindowsFilesAreNotChecked()
    {
        Assert.True(IdentityRules.IsExempt("System", @"C:\Windows"));
        Assert.True(IdentityRules.IsExempt(@"C:\Windows\System32\svchost.exe", @"C:\Windows"));
        Assert.True(IdentityRules.IsExempt(@"c:\windows\explorer.exe", @"C:\Windows\"));
        Assert.False(IdentityRules.IsExempt(@"C:\WindowsApps2\app.exe", @"C:\Windows"));
        Assert.False(IdentityRules.IsExempt(@"C:\Program Files\App\app.exe", @"C:\Windows"));
    }

    [Fact]
    public void ExemptProgramsAreNotRecorded()
    {
        var windows = Path.Combine(_dir, "Windows");
        Directory.CreateDirectory(windows);
        var app = Path.Combine(windows, "explorer.exe");
        File.WriteAllText(app, "x");

        Assert.Null(_guard.Record(app, Now));
        Assert.Empty(_guard.Review([app], Now));
        Assert.Null(_store.Known(app));
    }

    [Fact]
    public void ADamagedStoreIsTreatedAsEmpty()
    {
        File.WriteAllText(_store.FilePath, "{ not json");

        Assert.Empty(_store.Changed());
        Assert.Null(_store.Known(@"C:\x.exe"));
    }

    [Fact]
    public void CompareUsesContentsThenPublisher()
    {
        var was = new ProgramIdentity("a", "P", "AA", 1, Now, Now);

        Assert.Equal(IdentityChange.Same, IdentityRules.Compare(was, was with { Sha256 = "aa" }));
        Assert.Equal(IdentityChange.Updated, IdentityRules.Compare(was, was with { Sha256 = "BB" }));
        Assert.Equal(IdentityChange.Changed, IdentityRules.Compare(was, was with { Sha256 = "BB", Publisher = "Q" }));
        Assert.Equal(IdentityChange.Changed, IdentityRules.Compare(was with { Publisher = null }, was with { Sha256 = "BB", Publisher = null }));
    }

    private string Program(string name, string contents)
    {
        var path = Path.Combine(_dir, name);
        File.WriteAllText(path, contents);
        File.SetLastWriteTimeUtc(path, Now.AddDays(-1));
        return path;
    }

    private static void Rewrite(string path, string contents)
    {
        var before = File.GetLastWriteTimeUtc(path);
        File.WriteAllText(path, contents);
        File.SetLastWriteTimeUtc(path, before.AddHours(1));
    }

    private sealed class FakeSignatures : ISignatureReader
    {
        public Dictionary<string, string> Signers { get; } = new(StringComparer.OrdinalIgnoreCase);

        public string? Publisher(string path) => Signers.GetValueOrDefault(path);
    }
}
