using CrioFire.Core;
using CrioFire.Core.Api;

namespace CrioFire.Tests;

public sealed class StoreAppTests : IDisposable
{
    private const string Terminal = @"C:\Program Files\WindowsApps\Microsoft.WindowsTerminal_1.21.2361.0_x64__8wekyb3d8bbwe\WindowsTerminal.exe";
    private const string TerminalKey = "pkg:Microsoft.WindowsTerminal_8wekyb3d8bbwe";

    private readonly string _root = Path.Combine(Path.GetTempPath(), "criofire-store-" + Guid.NewGuid().ToString("N"), "WindowsApps");

    public void Dispose()
    {
        var parent = Path.GetDirectoryName(_root)!;
        if (Directory.Exists(parent))
        {
            Directory.Delete(parent, recursive: true);
        }
    }

    [Fact]
    public void TheFamilyComesFromTheVersionedFolder()
    {
        Assert.Equal("Microsoft.WindowsTerminal_8wekyb3d8bbwe", StoreApps.FamilyFromPath(Terminal));
        Assert.Equal("Microsoft.WindowsTerminal_8wekyb3d8bbwe", StoreApps.FamilyFromPath(@"D:\WindowsApps\Microsoft.WindowsTerminal_1.22.0.0_arm64__8wekyb3d8bbwe\sub\x.exe"));
        Assert.Null(StoreApps.FamilyFromPath(@"C:\Program Files\App\app.exe"));
        Assert.Null(StoreApps.FamilyFromPath(@"C:\Program Files\WindowsApps\NotAPackage\app.exe"));
        Assert.Null(StoreApps.FamilyFromPath(null));
    }

    [Fact]
    public void FolderNamesMustLookLikePackages()
    {
        Assert.Equal("Microsoft.Foo_abc", StoreApps.FamilyFromFolderName("Microsoft.Foo_1.0.0.0_neutral_~_abc"));
        Assert.Null(StoreApps.FamilyFromFolderName("Microsoft.Foo_notaversion_x64__abc"));
        Assert.Null(StoreApps.FamilyFromFolderName("Deleted"));
    }

    [Fact]
    public void RulesForStoreAppsAreKeyedByFamily()
    {
        Assert.Equal(TerminalKey, KnownApps.Normalize(Terminal));
        Assert.Equal(TerminalKey, KnownApps.Normalize(TerminalKey));
        Assert.Equal(TerminalKey, KnownApps.RuleKey(Terminal));
        Assert.True(KnownApps.SameApp(TerminalKey, Terminal));
        Assert.True(KnownApps.SameApp(TerminalKey, Terminal.Replace("1.21.2361.0", "1.22.100.0", StringComparison.Ordinal)));
        Assert.False(KnownApps.SameApp(TerminalKey, @"C:\Program Files\App\app.exe"));
        Assert.Equal("Microsoft.WindowsTerminal (Store app)", KnownApps.DisplayName(TerminalKey));
        Assert.Equal(@"C:\Program Files\WindowsApps", StoreApps.RootFromPath(Terminal));
    }

    [Fact]
    public void InstalledProgramsAreFoundInMainPackagesOnly()
    {
        var main = Directory.CreateDirectory(Path.Combine(_root, "Contoso.Chat_2.0.0.0_x64__pub123")).FullName;
        var resources = Directory.CreateDirectory(Path.Combine(_root, "Contoso.Chat_2.0.0.0_neutral_~_pub123")).FullName;
        Directory.CreateDirectory(Path.Combine(_root, "Contoso.Chat_2.0.0.0_x64__otherpub"));
        Directory.CreateDirectory(Path.Combine(main, "bin"));
        File.WriteAllText(Path.Combine(main, "chat.exe"), "x");
        File.WriteAllText(Path.Combine(main, "bin", "helper.exe"), "x");
        File.WriteAllText(Path.Combine(main, "readme.txt"), "x");
        File.WriteAllText(Path.Combine(resources, "nothere.exe"), "x");

        var folders = StoreApps.InstallFolders("Contoso.Chat_pub123", [_root]);
        var programs = StoreApps.Programs("Contoso.Chat_pub123", [_root]).Select(Path.GetFileName).Order().ToList();

        Assert.Equal(main, Assert.Single(folders));
        Assert.Equal("chat.exe,helper.exe", string.Join(",", programs));
        Assert.Equal("Contoso.Chat_2.0.0.0_x64__pub123", StoreApps.InstalledSignature("Contoso.Chat_pub123", [_root]));
        Assert.Empty(StoreApps.InstallFolders("Contoso.Chat_pub123", [Path.Combine(_root, "missing")]));
    }

    [Fact]
    public void AStoreAppWithARuleIsNotAskedAbout()
    {
        var tracker = new AlertTracker();
        var rule = new RuleInfo(1, nameof(FilterKind.AppRule), "allow", "out", TerminalKey, "outbound IPv4", "x");
        var blocked = new EventInfo(DateTime.UtcNow, Terminal, "TCP", null, "10.0.0.1:443", "out", true, 7, nameof(FilterKind.DefaultBlock));

        Assert.Empty(tracker.NewAlerts([blocked], [rule]));
    }

    [Fact]
    public void StoreAppsAreNotCheckedByFileIdentity()
    {
        Assert.True(IdentityRules.IsExempt(TerminalKey, @"C:\Windows"));
    }
}
