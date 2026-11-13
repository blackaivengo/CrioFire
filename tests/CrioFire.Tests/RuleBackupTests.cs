using CrioFire.Core;

namespace CrioFire.Tests;

public sealed class RuleBackupTests : IDisposable
{
    private static readonly DateTime Now = new(2026, 11, 12, 21, 0, 0, DateTimeKind.Utc);
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "criofire-backups-" + Guid.NewGuid().ToString("N"));

    public void Dispose()
    {
        if (Directory.Exists(_dir))
        {
            Directory.Delete(_dir, recursive: true);
        }
    }

    [Fact]
    public void ExportHasOneEntryPerRuleNotPerFilter()
    {
        var set = RuleBackup.FromFilters(Filters(), [new AutoRuleSetting("svchost", true)], [@"C:\Temp\once.exe"], "PC1", Now);

        Assert.Equal("ask", set.Mode);
        Assert.Equal("PC1", set.Computer);
        var chat = Assert.Single(set.Programs, p => p.App == @"C:\Apps\chat.exe");
        Assert.Equal("allow", chat.Action);
        Assert.Equal("both", chat.Direction);
        Assert.DoesNotContain(set.Programs, p => p.App == @"C:\Temp\once.exe");   // temporary
        var net = Assert.Single(set.Network);
        Assert.Equal("445", net.Ports);
        Assert.Equal("in", net.Direction);
        Assert.Equal("DiagTrack", Assert.Single(set.Services).Service);
        Assert.Equal(3, set.Count);
    }

    [Fact]
    public void AFileSurvivesTheRoundTrip()
    {
        var set = RuleBackup.FromFilters(Filters(), [new AutoRuleSetting("system", false)], null, "PC1", Now);

        var back = RuleBackup.FromJson(RuleBackup.ToJson(set));

        Assert.Equal(RuleBackup.Fingerprint(set), RuleBackup.Fingerprint(back));
        Assert.Null(RuleBackup.Validate(back));
        Assert.Equal(Now, back.CreatedUtc);
    }

    [Fact]
    public void TheFingerprintIgnoresWhenAndWhere()
    {
        var set = RuleBackup.FromFilters(Filters(), [], null, "PC1", Now);

        Assert.Equal(RuleBackup.Fingerprint(set), RuleBackup.Fingerprint(set with { CreatedUtc = Now.AddDays(1), Computer = "PC2" }));
        Assert.NotEqual(RuleBackup.Fingerprint(set), RuleBackup.Fingerprint(set with { Mode = "learning" }));
    }

    [Fact]
    public void MergeAddsAndChangesAndReplaceAlsoRemoves()
    {
        var current = new RuleSet
        {
            Mode = "ask",
            Programs = [new(@"C:\a.exe", "allow", "out"), new(@"C:\b.exe", "block", "out"), new(@"C:\old.exe", "allow", "out")],
            Services = [new("DiagTrack", "block", "out")],
        };
        var incoming = new RuleSet
        {
            Mode = "allowlist",
            Programs = [new(@"C:\a.exe", "allow", "out"), new(@"C:\b.exe", "allow", "out"), new(@"C:\new.exe", "block", "out"), new(@"C:\gone.exe", "allow", "out")],
            Network = [new("block", "in", "tcp", "445", "", null)],
            Services = [new("DiagTrack", "block", "out")],
        };
        bool Exists(string p) => p != @"C:\gone.exe";

        var merge = RuleBackup.Plan(current, incoming, ImportMode.Merge, Exists);
        var replace = RuleBackup.Plan(current, incoming, ImportMode.Replace, Exists, applyMode: true);

        Assert.Equal(2, merge.Add);      // new.exe, the network rule
        Assert.Equal(1, merge.Change);   // b.exe block -> allow
        Assert.Equal(2, merge.Same);     // a.exe, DiagTrack
        Assert.Equal(0, merge.Remove);
        Assert.Equal(@"C:\gone.exe", Assert.Single(merge.Missing));
        Assert.Null(merge.ModeChange);
        Assert.Equal(1, replace.Remove); // old.exe
        Assert.Equal("allowlist", replace.ModeChange);
    }

    [Fact]
    public void TheKernelAndStoreAppsAreNeverMissing()
    {
        var incoming = new RuleSet { Programs = [new("System", "block", "in"), new("pkg:Contoso.Chat_pub", "allow", "out")] };

        var plan = RuleBackup.Plan(new RuleSet(), incoming, ImportMode.Merge, _ => false);

        Assert.Empty(plan.Missing);
        Assert.Equal(2, plan.Add);
    }

    [Fact]
    public void BadFilesAreRefusedWithAReason()
    {
        Assert.Throws<ArgumentException>(() => RuleBackup.FromJson("not json"));
        Assert.Throws<ArgumentException>(() => RuleBackup.FromJson("{\"format\":0}"));
        Assert.NotNull(RuleBackup.Validate(new RuleSet { Format = 99 }));
        Assert.NotNull(RuleBackup.Validate(new RuleSet { Programs = [new(@"C:\a.exe", "maybe", "out")] }));
        Assert.NotNull(RuleBackup.Validate(new RuleSet { Network = [new("block", "in", "tcp", "99999", "", null)] }));
        Assert.NotNull(RuleBackup.Validate(new RuleSet { Mode = "chaos" }));
        Assert.Null(RuleBackup.Validate(new RuleSet { Network = [new("block", "out", "any", "*", "10.0.0.0/8", null)] }));
    }

    [Fact]
    public void BackupsAreSavedListedAndLoaded()
    {
        var store = new RuleBackupStore(_dir);
        var set = RuleBackup.FromFilters(Filters(), [], null, "PC1", Now);

        var name = store.Save(set, "auto");
        var again = store.Save(set with { CreatedUtc = Now.AddMinutes(5) }, "before-import");

        Assert.Equal("rules-20261112-210000-auto.json", name);
        var list = store.List();
        Assert.Equal(2, list.Count);
        Assert.Equal(again, list[0].Name);
        Assert.Equal("before-import", list[0].Reason);
        Assert.Equal(4, list[0].Rules);   // chat.exe, once.exe (not marked temporary here), the network and service rule
        Assert.Equal(RuleBackup.Fingerprint(set), RuleBackup.Fingerprint(store.Load(name)));
        Assert.Equal(RuleBackup.Fingerprint(set), store.LatestFingerprint());
    }

    [Fact]
    public void OnlyTheNewestBackupsAreKept()
    {
        var store = new RuleBackupStore(_dir);
        var set = new RuleSet { Programs = [new(@"C:\a.exe", "allow", "out")] };
        for (var i = 0; i < RuleBackupStore.Keep + 5; i++)
        {
            store.Save(set with { CreatedUtc = Now.AddMinutes(i) }, "auto");
        }

        var list = store.List();
        Assert.Equal(RuleBackupStore.Keep, list.Count);
        Assert.Equal(Now.AddMinutes(RuleBackupStore.Keep + 4), list[0].CreatedUtc);
    }

    [Fact]
    public void LoadRefusesAnythingButABackupName()
    {
        var store = new RuleBackupStore(_dir);
        Assert.Throws<ArgumentException>(() => store.Load(@"..\..\secrets.json"));
        Assert.Throws<ArgumentException>(() => store.Load("C:/x/rules-1.json"));
        Assert.Throws<ArgumentException>(() => store.Load("rules-20990101-000000-auto.json"));
    }

    private static List<CrioFireFilter> Filters()
    {
        var chat = @"C:\Apps\chat.exe";
        var once = @"C:\Temp\once.exe";
        var net = NetRule.Create(RuleAction.Block, TrafficDirection.Inbound, NetProtocol.Tcp, "445", null, null, out _)!;
        var svc = new ServiceRule(RuleAction.Block, TrafficDirection.Outbound, "DiagTrack");
        return
        [
            new(1, "default", FilterLayers.ConnectV4, null, FilterKind.DefaultBlock, Mode: FirewallMode.Ask),
            new(2, "chat", FilterLayers.ConnectV4, new RuleDescription(RuleAction.Allow, TrafficDirection.Both, chat)),
            new(3, "chat", FilterLayers.ConnectV6, new RuleDescription(RuleAction.Allow, TrafficDirection.Both, chat)),
            new(4, "once", FilterLayers.ConnectV4, new RuleDescription(RuleAction.Allow, TrafficDirection.Outbound, once)),
            new(5, "net", FilterLayers.ConnectV4, null, FilterKind.NetRule, Net: net),
            new(6, "net", FilterLayers.ConnectV6, null, FilterKind.NetRule, Net: net),
            new(7, "svc", FilterLayers.ConnectV4, null, FilterKind.ServiceRule, Service: svc),
        ];
    }
}
