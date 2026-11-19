using CrioFire.Cli;
using CrioFire.Core;
using CrioFire.Core.Api;

namespace CrioFire.Tests;

public sealed class SelfProtectionTests : IDisposable
{
    private static readonly DateTime Now = new(2026, 11, 18, 12, 0, 0, DateTimeKind.Utc);
    private readonly string _folder = Path.Combine(Path.GetTempPath(), "criofire-integrity-" + Guid.NewGuid().ToString("N"));

    public SelfProtectionTests()
    {
        Directory.CreateDirectory(Path.Combine(_folder, "Strings"));
        File.WriteAllText(Path.Combine(_folder, "criofire-svc.exe"), "service");
        File.WriteAllText(Path.Combine(_folder, "criofire.exe"), "cli");
        File.WriteAllText(Path.Combine(_folder, "CrioFire.Core.dll"), "core");
        File.WriteAllText(Path.Combine(_folder, "System.Runtime.dll"), "runtime");
        File.WriteAllText(Path.Combine(_folder, "Strings", "de.json"), "{}");
    }

    public void Dispose() => Directory.Delete(_folder, recursive: true);

    private IntegrityManifest Baseline()
    {
        var manifest = FileIntegrity.Create(_folder, "1.2.0", Now);
        FileIntegrity.Save(_folder, manifest);
        return FileIntegrity.Load(_folder)!;
    }

    [Fact]
    public void AnUntouchedFolderIsOk()
    {
        var manifest = Baseline();
        Assert.Equal(5, manifest.Files.Count);
        Assert.Contains(manifest.Files, f => f.Path == "Strings/de.json");
        Assert.DoesNotContain(manifest.Files, f => f.Path == IntegrityManifest.FileName);

        var result = FileIntegrity.Verify(_folder, manifest, Now);
        Assert.Equal(IntegrityStates.Ok, result.State);
        Assert.Empty(result.Findings);
        Assert.Equal(5, result.Files);
        Assert.False(result.Signed);
    }

    [Fact]
    public void ChangedMissingAndAddedProgramFilesAreFound()
    {
        var manifest = Baseline();
        File.WriteAllText(Path.Combine(_folder, "criofire.exe"), "ilc");                 // same size, other contents
        File.Delete(Path.Combine(_folder, "System.Runtime.dll"));
        File.WriteAllText(Path.Combine(_folder, "version.dll"), "planted");              // a DLL next to the programs
        File.WriteAllText(Path.Combine(_folder, "notes.txt"), "harmless");               // not a program: ignored

        var result = FileIntegrity.Verify(_folder, manifest, Now);
        Assert.Equal(IntegrityStates.Problems, result.State);
        Assert.Equal(
            ["criofire.exe:changed", "System.Runtime.dll:missing", "version.dll:unexpected"],
            result.Findings.Select(f => $"{f.Path}:{f.Kind}").Order(StringComparer.OrdinalIgnoreCase));
    }

    [Fact]
    public void NoManifestIsUncheckedAndADamagedOneIsAProblem()
    {
        Assert.Null(FileIntegrity.Load(_folder));
        Assert.Equal(IntegrityStates.Unchecked, FileIntegrity.Verify(_folder, null, Now).State);

        File.WriteAllText(Path.Combine(_folder, IntegrityManifest.FileName), "{ not json");
        var result = FileIntegrity.Verify(_folder, FileIntegrity.Load(_folder), Now);
        Assert.Equal(IntegrityStates.Problems, result.State);
    }

    [Fact]
    public void TheBuildScriptsManifestFormatIsRead()
    {
        // As build/write-integrity.ps1 writes it.
        File.WriteAllText(Path.Combine(_folder, IntegrityManifest.FileName),
            """{ "version": "1.2.0", "createdUtc": "2026-11-18T12:00:00.0000000Z", "files": [ { "path": "criofire.exe", "sha256": "ABC", "size": 3 } ] }""");
        var manifest = FileIntegrity.Load(_folder)!;
        Assert.Equal("1.2.0", manifest.Version);
        Assert.Equal(new IntegrityFile("criofire.exe", "ABC", 3), Assert.Single(manifest.Files));
    }

    [Fact]
    public void AManifestCannotPointOutsideTheFolder()
    {
        var manifest = new IntegrityManifest { Files = [new IntegrityFile("../outside.exe", "00", 1)] };
        Assert.DoesNotContain(FileIntegrity.Verify(_folder, manifest, Now).Findings, f => f.Path.Contains("outside", StringComparison.Ordinal));
    }

    [Fact]
    public void OnASignedInstallEveryCrioFireProgramMustCarryThePublishersSignature()
    {
        var manifest = Baseline();
        SignatureInfo Signed(string who) => new(SignatureState.Valid, 0, who, who, "CA", null, null, "AA");
        var unsigned = new SignatureInfo(SignatureState.NotSigned, unchecked((int)0x800B0100), null, null, null, null, null, null);

        // Not signed at all (a build from source): signatures are not compared.
        var result = FileIntegrity.Verify(_folder, manifest, Now, _ => unsigned);
        Assert.Equal(IntegrityStates.Ok, result.State);
        Assert.False(result.Signed);

        // Signed: all three CrioFire programs by the same publisher; the runtime is not asked about.
        var asked = new List<string>();
        result = FileIntegrity.Verify(_folder, manifest, Now, p => { asked.Add(Path.GetFileName(p)); return Signed("CrioSoft LLC"); });
        Assert.Equal(IntegrityStates.Ok, result.State);
        Assert.True(result.Signed);
        Assert.DoesNotContain("System.Runtime.dll", asked);

        // One of them signed by someone else, one not signed.
        result = FileIntegrity.Verify(_folder, manifest, Now, p => Path.GetFileName(p) switch
        {
            "criofire.exe" => Signed("Someone Else"),
            "CrioFire.Core.dll" => unsigned,
            _ => Signed("CrioSoft LLC"),
        });
        Assert.Equal(["CrioFire.Core.dll:signature", "criofire.exe:signature"], result.Findings.Select(f => $"{f.Path}:{f.Kind}").Order(StringComparer.Ordinal));
    }

    [Fact]
    public void AServiceThatEndedWithoutACleanStopIsNoticedAtTheNextStart()
    {
        var marker = Path.Combine(_folder, "state", "running.txt");

        var first = new SelfProtection(_folder, markerPath: marker);
        Assert.Null(first.NoteStart(Now));                       // first start ever
        first.Heartbeat(Now.AddMinutes(5));                      // ...and then it is killed

        var second = new SelfProtection(_folder, markerPath: marker);
        Assert.Equal(Now.AddMinutes(5), second.NoteStart(Now.AddMinutes(6)));
        Assert.Equal(Now.AddMinutes(5), second.UnexpectedStopUtc);
        second.NoteCleanStop();                                  // stopped properly this time

        var third = new SelfProtection(_folder, markerPath: marker);
        Assert.Null(third.NoteStart(Now.AddMinutes(10)));
        Assert.Null(third.UnexpectedStopUtc);
    }

    [Fact]
    public void TheCheckKeepsItsLastResult()
    {
        Baseline();
        var self = new SelfProtection(_folder);
        Assert.Null(self.Latest);
        Assert.Equal(IntegrityStates.Ok, self.Check(Now).State);
        File.WriteAllText(Path.Combine(_folder, "wininet.dll"), "planted");
        Assert.Equal(IntegrityStates.Ok, self.Latest!.State);    // until the next check
        Assert.Equal("wininet.dll", Assert.Single(self.Check(Now).Findings).Path);
        Assert.Equal(IntegrityStates.Problems, self.Latest!.State);
    }

    [Fact]
    public void TheLockedServiceLeavesAdministratorsStartAndQueryOnly()
    {
        static string Rights(string sddl, string who) =>
            System.Text.RegularExpressions.Regex.Match(sddl, @"\(A;;([A-Z]+);;;" + who + @"\)").Groups[1].Value;
        static HashSet<string> Pairs(string rights) => Enumerable.Range(0, rights.Length / 2).Select(i => rights.Substring(i * 2, 2)).ToHashSet();

        var locked = Pairs(Rights(ServiceGuard.LockedSddl, "BA"));
        Assert.Contains("RP", locked);                           // start
        Assert.Contains("LC", locked);                           // query status
        foreach (var right in new[] { "WP", "DT", "DC", "SD", "WD", "WO" })   // stop, pause, change, delete, permissions, owner
        {
            Assert.DoesNotContain(right, locked);
            Assert.Contains(right, Pairs(Rights(ServiceGuard.UnlockedSddl, "BA")));
            Assert.Contains(right, Pairs(Rights(ServiceGuard.LockedSddl, "SY")));   // Windows Installer and the service itself
        }

        // The process: administrators may not end it (0x1), write its memory (0x20) or start threads in it (0x2).
        var admins = Convert.ToUInt32(System.Text.RegularExpressions.Regex.Match(ServiceGuard.ProcessSddl, @"\(A;;0x([0-9a-fA-F]+);;;BA\)").Groups[1].Value, 16);
        Assert.Equal(0u, admins & (0x1 | 0x2 | 0x8 | 0x20 | 0x40 | 0x800));
        Assert.NotEqual(0u, admins & 0x1000);                    // but may see that it runs
    }

    [Fact]
    public void OnlyAnElevatedAdministratorMayStopTheService()
    {
        var stops = 0;
        var self = new SelfProtection(_folder) { StopRequested = () => stops++ };
        var handler = new ApiHandler(null!, selfProtection: self);
        var stop = new ApiRequest { Op = ApiOps.StopService };

        Assert.False(handler.Handle(stop, ClientRights.ReadOnly).Ok);
        var app = handler.Handle(stop, ClientRights.CrioFireApp);      // CrioFire's own app, not elevated
        Assert.False(app.Ok);
        Assert.Equal(ApiOps.ApprovalRequired, app.Code);
        Assert.Equal(0, stops);

        Assert.True(handler.Handle(stop, ClientRights.Administrator).Ok);
        Assert.Equal(1, stops);

        // No service behind the handler (the command line working directly): nothing to stop.
        Assert.False(new ApiHandler(null!, selfProtection: new SelfProtection(_folder)).Handle(stop, ClientRights.Administrator).Ok);
    }

    [Fact]
    public void AnyoneReadsTheLastFileCheckButOnlyCrioFireChecksAgain()
    {
        Baseline();
        var self = new SelfProtection(_folder);
        var handler = new ApiHandler(null!, selfProtection: self);
        var again = new ApiRequest { Op = ApiOps.Integrity, All = true };

        Assert.Equal(IntegrityStates.Ok, handler.Handle(again, ClientRights.ReadOnly).Integrity!.State);   // the first check
        File.WriteAllText(Path.Combine(_folder, "wininet.dll"), "planted");
        Assert.Equal(IntegrityStates.Ok, handler.Handle(again, ClientRights.ReadOnly).Integrity!.State);   // still the last result
        Assert.Equal(IntegrityStates.Problems, handler.Handle(again, ClientRights.CrioFireApp).Integrity!.State);
        Assert.Equal(IntegrityStates.Problems, handler.Handle(new ApiRequest { Op = ApiOps.Integrity }, ClientRights.ReadOnly).Integrity!.State);
    }

    [Fact]
    public void TheCommandsParse()
    {
        Assert.Equal(CommandKind.Verify, CommandLine.Parse(["verify"], out var e1).Kind);
        Assert.Null(e1);
        Assert.Equal(CommandKind.ServiceStop, CommandLine.Parse(["service", "stop"], out _).Kind);
        Assert.Equal(CommandKind.ServiceStart, CommandLine.Parse(["service", "START"], out _).Kind);
        Assert.Equal(CommandKind.Help, CommandLine.Parse(["service"], out var e2).Kind);
        Assert.Equal("Usage: criofire service stop|start", e2);
        Assert.Equal(CommandKind.Help, CommandLine.Parse(["service", "delete"], out _).Kind);
    }
}
