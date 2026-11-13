using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace CrioFire.Core;

/// <summary>
/// What a program file was when the user allowed it: who signed it, and a fingerprint of its
/// contents. A rule only names a path, so without this a different program put at that path, or
/// a tampered copy, would inherit the permission.
/// </summary>
/// <param name="App">The program path, as in the rule.</param>
/// <param name="Publisher">The verified Authenticode signer ("Google LLC"), or null when the file has no valid signature.</param>
/// <param name="Sha256">SHA-256 of the file, hex.</param>
public sealed record ProgramIdentity(string App, string? Publisher, string Sha256, long Size, DateTime LastWriteUtc, DateTime RecordedUtc)
{
    public bool IsSigned => Publisher is not null;

    /// <summary>Reads a program file's identity, or null when the file does not exist (or cannot be read).</summary>
    public static ProgramIdentity? Read(string path, ISignatureReader signatures, DateTime nowUtc)
    {
        ArgumentNullException.ThrowIfNull(signatures);
        try
        {
            var file = new FileInfo(path);
            if (!file.Exists)
            {
                return null;
            }

            string hash;
            using (var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
            {
                hash = Convert.ToHexString(SHA256.HashData(stream));
            }

            return new ProgramIdentity(path, signatures.Publisher(path), hash, file.Length, file.LastWriteTimeUtc, nowUtc);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    /// <summary>True when size and modification time still match, so the file need not be read again.</summary>
    public bool LooksUnchanged(FileInfo file)
    {
        ArgumentNullException.ThrowIfNull(file);
        return file.Exists && file.Length == Size && file.LastWriteTimeUtc == LastWriteUtc;
    }

    /// <summary>How to describe the file to a person: its publisher, or that it is unsigned.</summary>
    public string Who => Publisher ?? "unsigned";
}

/// <summary>Who signed a file. An interface so the logic can be tested without real signatures.</summary>
public interface ISignatureReader
{
    /// <summary>The signer's name when the file has a valid Authenticode signature, otherwise null.</summary>
    string? Publisher(string path);
}

/// <summary>How a program compares with what was recorded when it was allowed.</summary>
public enum IdentityChange
{
    /// <summary>The same file.</summary>
    Same,

    /// <summary>A new file from the same publisher: a normal update. Accepted silently.</summary>
    Updated,

    /// <summary>A different publisher, a signature that disappeared, or an unsigned file whose contents changed.</summary>
    Changed,
}

/// <summary>A program whose file changed since the user allowed it.</summary>
/// <param name="Direction">The direction of the allow rule it had: out, in or both.</param>
/// <param name="Blocked">True when CrioFire replaced the allow rule with a block rule (Ask and Allow-list mode).</param>
public sealed record ChangedProgram(
    string App,
    string? WasPublisher,
    string? NowPublisher,
    string WasSha256,
    string NowSha256,
    string Direction,
    bool Blocked,
    DateTime DetectedUtc);

/// <summary>A finding of one review: the program, and what was and is now on disk.</summary>
public sealed record IdentityFinding(string App, IdentityChange Change, ProgramIdentity Was, ProgramIdentity Now);

/// <summary>The rules for comparing identities, and which programs are not checked.</summary>
public static class IdentityRules
{
    public static IdentityChange Compare(ProgramIdentity was, ProgramIdentity now)
    {
        ArgumentNullException.ThrowIfNull(was);
        ArgumentNullException.ThrowIfNull(now);
        if (string.Equals(was.Sha256, now.Sha256, StringComparison.OrdinalIgnoreCase))
        {
            return IdentityChange.Same;
        }

        return was.Publisher is not null && string.Equals(was.Publisher, now.Publisher, StringComparison.Ordinal)
            ? IdentityChange.Updated
            : IdentityChange.Changed;
    }

    /// <summary>
    /// Programs that are not checked: the Windows kernel ("System"), and files in the Windows
    /// folder, which only Windows itself may change and which Windows Update replaces often.
    /// </summary>
    public static bool IsExempt(string app, string? windowsFolder = null)
    {
        if (KnownApps.IsKernel(app))
        {
            return true;
        }

        var windows = windowsFolder ?? Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        if (string.IsNullOrEmpty(windows))
        {
            return false;
        }

        var folder = windows.TrimEnd('\\', '/');
        return app.StartsWith(folder + '\\', StringComparison.OrdinalIgnoreCase)
            || app.StartsWith(folder + '/', StringComparison.OrdinalIgnoreCase);
    }
}

/// <summary>
/// Remembers program identities (%ProgramData%\criofire\program-identities.json): what each
/// allowed program was, and the programs that changed since. Thread-safe within the process.
/// </summary>
public sealed class ProgramIdentityStore(string path)
{
    private static readonly Lock Gate = new();

    public static string DefaultPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "criofire", "program-identities.json");

    public string FilePath { get; } = path;

    public ProgramIdentity? Known(string app)
    {
        lock (Gate)
        {
            return Load().Known.FirstOrDefault(k => Same(k.App, app));
        }
    }

    public IReadOnlyList<ChangedProgram> Changed()
    {
        lock (Gate)
        {
            return Load().Changed;
        }
    }

    public ChangedProgram? Changed(string app)
    {
        lock (Gate)
        {
            return Load().Changed.FirstOrDefault(c => Same(c.App, app));
        }
    }

    /// <summary>Records what the program is now; it is no longer listed as changed.</summary>
    public void Record(ProgramIdentity identity)
    {
        ArgumentNullException.ThrowIfNull(identity);
        lock (Gate)
        {
            var data = Load();
            data.Known.RemoveAll(k => Same(k.App, identity.App));
            data.Known.Add(identity);
            data.Changed.RemoveAll(c => Same(c.App, identity.App));
            Save(data);
        }
    }

    public void MarkChanged(ChangedProgram changed)
    {
        ArgumentNullException.ThrowIfNull(changed);
        lock (Gate)
        {
            var data = Load();
            data.Changed.RemoveAll(c => Same(c.App, changed.App));
            data.Changed.Add(changed);
            Save(data);
        }
    }

    /// <summary>Forgets a program entirely (its rule was removed, or the user blocked it).</summary>
    public void Forget(string app)
    {
        lock (Gate)
        {
            var data = Load();
            var removed = data.Known.RemoveAll(k => Same(k.App, app)) + data.Changed.RemoveAll(c => Same(c.App, app));
            if (removed > 0)
            {
                Save(data);
            }
        }
    }

    /// <summary>Forgets everything (every rule was removed).</summary>
    public void Clear()
    {
        lock (Gate)
        {
            if (File.Exists(FilePath))
            {
                File.Delete(FilePath);
            }
        }
    }

    private static bool Same(string a, string b) => string.Equals(a, b, StringComparison.OrdinalIgnoreCase);

    private IdentityData Load()
    {
        if (!File.Exists(FilePath))
        {
            return new IdentityData();
        }

        try
        {
            return JsonSerializer.Deserialize(File.ReadAllText(FilePath), ProgramIdentityJson.Default.IdentityData) ?? new IdentityData();
        }
        catch (JsonException)
        {
            return new IdentityData();   // a damaged file must not break the firewall; identities are recorded again
        }
    }

    private void Save(IdentityData data)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(FilePath))!);
        var temp = FilePath + ".tmp";
        File.WriteAllText(temp, JsonSerializer.Serialize(data, ProgramIdentityJson.Default.IdentityData));
        File.Move(temp, FilePath, overwrite: true);
    }
}

internal sealed class IdentityData
{
    public List<ProgramIdentity> Known { get; set; } = [];

    public List<ChangedProgram> Changed { get; set; } = [];
}

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase, WriteIndented = true)]
[JsonSerializable(typeof(IdentityData))]
internal sealed partial class ProgramIdentityJson : JsonSerializerContext
{
}

/// <summary>
/// Checks that allowed programs are still the files the user allowed. A new version from the same
/// publisher is accepted (that is how programs update); anything else is reported as changed, and
/// the caller blocks it until the user allows it again.
/// </summary>
public sealed class IdentityGuard(ProgramIdentityStore store, ISignatureReader signatures, string? windowsFolder = null)
{
    public ProgramIdentityStore Store { get; } = store;

    /// <summary>The user allowed the program: remember what it is now. Returns null for exempt or missing files.</summary>
    public ProgramIdentity? Record(string app, DateTime nowUtc)
    {
        if (IdentityRules.IsExempt(app, windowsFolder))
        {
            return null;
        }

        var identity = ProgramIdentity.Read(app, signatures, nowUtc);
        if (identity is null)
        {
            Store.Forget(app);
            return null;
        }

        Store.Record(identity);
        return identity;
    }

    /// <summary>
    /// Compares each allowed program with its recorded identity. Programs seen for the first time
    /// are recorded as they are; updates from the same publisher are recorded silently; files that
    /// are gone are skipped (there is nothing to run). Returns updates and changes.
    /// </summary>
    public IReadOnlyList<IdentityFinding> Review(IEnumerable<string> allowedApps, DateTime nowUtc)
    {
        ArgumentNullException.ThrowIfNull(allowedApps);
        var findings = new List<IdentityFinding>();
        foreach (var app in allowedApps.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            if (IdentityRules.IsExempt(app, windowsFolder) || Store.Changed(app) is not null)
            {
                continue;
            }

            var file = new FileInfo(app);
            if (!file.Exists)
            {
                continue;
            }

            var known = Store.Known(app);
            if (known is null)
            {
                Record(app, nowUtc);
                continue;
            }

            if (known.LooksUnchanged(file))
            {
                continue;
            }

            var now = ProgramIdentity.Read(app, signatures, nowUtc);
            if (now is null)
            {
                continue;
            }

            var change = IdentityRules.Compare(known, now);
            if (change != IdentityChange.Changed)
            {
                Store.Record(now);   // the same file touched, or an update from the same publisher
            }

            if (change != IdentityChange.Same)
            {
                findings.Add(new IdentityFinding(app, change, known, now));
            }
        }

        return findings;
    }

    /// <summary>
    /// Reviews the programs CrioFire allows and blocks the ones that changed, when the firewall
    /// blocks programs without a rule (Ask and Allow-list mode). In Learning mode programs without
    /// a rule may connect anyway, so a changed program is only reported. Returns the changes found.
    /// </summary>
    public IReadOnlyList<ChangedProgram> Enforce(WfpEngine engine, DateTime nowUtc, TemporaryRuleStore? temporaryRules = null)
    {
        ArgumentNullException.ThrowIfNull(engine);
        var filters = engine.ListFilters();
        var allows = filters
            .Where(f => f.Kind == FilterKind.AppRule && f.Rule is { Action: RuleAction.Allow })
            .GroupBy(f => f.Rule!.AppPath, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.Select(f => f.Rule!.Direction).Aggregate((a, b) => a | b), StringComparer.OrdinalIgnoreCase);
        if (allows.Count == 0)
        {
            return [];
        }

        var mode = filters.FirstOrDefault(f => f.Kind == FilterKind.DefaultBlock)?.Mode ?? FirewallMode.Learning;
        var changes = new List<ChangedProgram>();
        foreach (var finding in Review(allows.Keys, nowUtc).Where(f => f.Change == IdentityChange.Changed))
        {
            var direction = allows[finding.App];
            var block = mode != FirewallMode.Learning;
            if (block)
            {
                engine.SetAppRule(finding.App, RuleAction.Block, direction);
                temporaryRules?.Remove(finding.App);   // an expiring allow must not remove the block later
            }

            var changed = new ChangedProgram(
                finding.App,
                finding.Was.Publisher,
                finding.Now.Publisher,
                finding.Was.Sha256,
                finding.Now.Sha256,
                RuleDescription.DirectionText(direction),
                block,
                nowUtc);
            Store.MarkChanged(changed);
            changes.Add(changed);
        }

        return changes;
    }
}

/// <summary>Reads Authenticode signatures with WinVerifyTrust (no network: cached revocation data only).</summary>
public sealed partial class AuthenticodeSignatures : ISignatureReader
{
    private const uint WtdUiNone = 2;
    private const uint WtdRevokeNone = 0;
    private const uint WtdChoiceFile = 1;
    private const uint WtdStateActionVerify = 1;
    private const uint WtdStateActionClose = 2;
    private const uint WtdCacheOnlyUrlRetrieval = 0x1000;

    private static readonly Guid GenericVerifyV2 = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    public string? Publisher(string path)
    {
        if (!IsTrusted(path))
        {
            return null;
        }

        try
        {
            using var signer = new X509Certificate2(X509Certificate.CreateFromSignedFile(path));
            var name = signer.GetNameInfo(X509NameType.SimpleName, forIssuer: false);
            return string.IsNullOrWhiteSpace(name) ? signer.Subject : name;
        }
        catch (CryptographicException)
        {
            return null;
        }
    }

    private static unsafe bool IsTrusted(string path)
    {
        fixed (char* file = path)
        {
            var fileInfo = new WintrustFileInfo
            {
                CbStruct = (uint)sizeof(WintrustFileInfo),
                FilePath = file,
            };
            var data = new WintrustData
            {
                CbStruct = (uint)sizeof(WintrustData),
                UiChoice = WtdUiNone,
                RevocationChecks = WtdRevokeNone,
                UnionChoice = WtdChoiceFile,
                File = &fileInfo,
                StateAction = WtdStateActionVerify,
                ProvFlags = WtdCacheOnlyUrlRetrieval,
            };
            var action = GenericVerifyV2;
            var result = WinVerifyTrust(-1, &action, &data);
            data.StateAction = WtdStateActionClose;
            _ = WinVerifyTrust(-1, &action, &data);
            return result == 0;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private unsafe struct WintrustFileInfo
    {
        public uint CbStruct;
        public char* FilePath;
        public nint File;
        public nint KnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    private unsafe struct WintrustData
    {
        public uint CbStruct;
        public nint PolicyCallbackData;
        public nint SipClientData;
        public uint UiChoice;
        public uint RevocationChecks;
        public uint UnionChoice;
        public WintrustFileInfo* File;
        public uint StateAction;
        public nint StateData;
        public nint UrlReference;
        public uint ProvFlags;
        public uint UiContext;
        public nint SignatureSettings;
    }

    [LibraryImport("wintrust.dll")]
    private static unsafe partial int WinVerifyTrust(nint window, Guid* action, WintrustData* data);
}
