using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using CrioFire.Core.Api;

namespace CrioFire.Core;

/// <summary>One file of the install, as the build made it.</summary>
public sealed record IntegrityFile(string Path, string Sha256, long Size);

/// <summary>
/// integrity.json in the install folder: every file CrioFire was built with, with its SHA-256.
/// The build writes it after the files are signed (build/write-integrity.ps1) and the installer
/// puts it next to them.
/// </summary>
public sealed record IntegrityManifest
{
    public const string FileName = "integrity.json";

    public string? Version { get; init; }

    public DateTime? CreatedUtc { get; init; }

    public List<IntegrityFile> Files { get; init; } = [];
}

/// <summary>What is wrong with a file of the install.</summary>
public static class IntegrityKinds
{
    /// <summary>Different contents from the file CrioFire was built with.</summary>
    public const string Changed = "changed";

    /// <summary>Gone.</summary>
    public const string Missing = "missing";

    /// <summary>A program file (exe, dll...) that is not part of CrioFire sits in its folder.</summary>
    public const string Unexpected = "unexpected";

    /// <summary>A CrioFire program whose signature is not valid, or not from the publisher that signed the service.</summary>
    public const string Signature = "signature";
}

/// <summary>The results of a check.</summary>
public static class IntegrityStates
{
    public const string Ok = "ok";
    public const string Problems = "problems";

    /// <summary>No integrity.json: a build made without it (from source), so nothing to compare with.</summary>
    public const string Unchecked = "unchecked";
}

/// <summary>
/// Checks that the files in CrioFire's folder are the ones it was built and installed with:
/// every file against the SHA-256 in integrity.json, no program file added, and, when the
/// service is signed, CrioFire's own programs signed by the same publisher.
/// </summary>
public static class FileIntegrity
{
    /// <summary>Files that Windows can load as code: one that appears in the folder uninvited is a finding.</summary>
    private static readonly HashSet<string> ProgramExtensions = new(StringComparer.OrdinalIgnoreCase)
        { ".exe", ".dll", ".sys", ".com", ".scr", ".ocx", ".cpl", ".drv" };

    /// <summary>The program whose signature the others are compared with.</summary>
    public const string ServiceProgram = "criofire-svc.exe";

    public static IntegrityManifest Create(string folder, string? version, DateTime nowUtc)
    {
        var root = Path.GetFullPath(folder);
        var files = Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories)
            .Select(f => Path.GetRelativePath(root, f).Replace('\\', '/'))
            .Where(p => !IsManifest(p))
            .Order(StringComparer.OrdinalIgnoreCase)
            .Select(p => new IntegrityFile(p, Hash(Path.Combine(root, p)), new FileInfo(Path.Combine(root, p)).Length))
            .ToList();
        return new IntegrityManifest { Version = version, CreatedUtc = nowUtc, Files = files };
    }

    public static IntegrityManifest? Load(string folder)
    {
        var path = Path.Combine(folder, IntegrityManifest.FileName);
        try
        {
            return File.Exists(path) ? JsonSerializer.Deserialize(File.ReadAllText(path), IntegrityJson.Default.IntegrityManifest) : null;
        }
        catch (Exception ex) when (ex is JsonException or IOException or UnauthorizedAccessException)
        {
            // A manifest that cannot be read is no manifest to trust: every file then counts as unknown.
            return new IntegrityManifest();
        }
    }

    public static void Save(string folder, IntegrityManifest manifest) =>
        File.WriteAllText(Path.Combine(folder, IntegrityManifest.FileName), JsonSerializer.Serialize(manifest, IntegrityJson.Default.IntegrityManifest));

    /// <summary>
    /// Compares the folder with its manifest. <paramref name="signature"/> reads a file's
    /// Authenticode signature (null: not checked, as on a build without Windows).
    /// </summary>
    public static IntegrityInfo Verify(string folder, IntegrityManifest? manifest, DateTime nowUtc, Func<string, SignatureInfo>? signature = null)
    {
        var root = Path.GetFullPath(folder);
        if (manifest is null)
        {
            return new IntegrityInfo(IntegrityStates.Unchecked, nowUtc, 0, [], false);
        }

        var findings = new List<IntegrityFinding>();
        var known = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var file in manifest.Files)
        {
            var relative = file.Path.Replace('\\', '/');
            known.Add(relative);
            var full = Path.GetFullPath(Path.Combine(root, relative));
            if (!full.StartsWith(Path.TrimEndingDirectorySeparator(root) + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
            {
                continue;   // a manifest must not send the check outside the folder
            }

            try
            {
                var info = new FileInfo(full);
                if (!info.Exists)
                {
                    findings.Add(new IntegrityFinding(IntegrityKinds.Missing, relative));
                }
                else if (info.Length != file.Size || !string.Equals(Hash(full), file.Sha256, StringComparison.OrdinalIgnoreCase))
                {
                    findings.Add(new IntegrityFinding(IntegrityKinds.Changed, relative));
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                findings.Add(new IntegrityFinding(IntegrityKinds.Changed, relative));
            }
        }

        if (manifest.Files.Count == 0)
        {
            findings.Add(new IntegrityFinding(IntegrityKinds.Changed, IntegrityManifest.FileName));
        }

        IEnumerable<string> present;
        try
        {
            present = Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories).Select(f => Path.GetRelativePath(root, f).Replace('\\', '/')).ToList();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            present = [];
        }

        foreach (var relative in present.Order(StringComparer.OrdinalIgnoreCase))
        {
            if (!known.Contains(relative) && !IsManifest(relative) && ProgramExtensions.Contains(Path.GetExtension(relative)))
            {
                findings.Add(new IntegrityFinding(IntegrityKinds.Unexpected, relative));
            }
        }

        var signed = false;
        if (signature is not null)
        {
            signed = CheckSignatures(root, known, signature, findings);
        }

        return new IntegrityInfo(findings.Count == 0 ? IntegrityStates.Ok : IntegrityStates.Problems, nowUtc, manifest.Files.Count, findings, signed);
    }

    /// <summary>
    /// When the service program is signed, every CrioFire program must be signed by the same
    /// publisher. Returns whether the install is a signed one.
    /// </summary>
    private static bool CheckSignatures(string root, HashSet<string> known, Func<string, SignatureInfo> signature, List<IntegrityFinding> findings)
    {
        SignatureInfo service;
        try
        {
            service = signature(Path.Combine(root, ServiceProgram));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or CryptographicException)
        {
            return false;
        }

        if (service.State == SignatureState.NotSigned)
        {
            return false;   // a build from source, or CI: nothing to compare
        }

        var publisher = service.Organization ?? service.Signer;
        foreach (var relative in known.Where(IsOwnProgram).Order(StringComparer.OrdinalIgnoreCase))
        {
            if (findings.Any(f => string.Equals(f.Path, relative, StringComparison.OrdinalIgnoreCase)))
            {
                continue;   // already reported as changed or missing
            }

            SignatureInfo info;
            try
            {
                info = signature(Path.Combine(root, relative));
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or CryptographicException)
            {
                findings.Add(new IntegrityFinding(IntegrityKinds.Signature, relative));
                continue;
            }

            if (info.State != SignatureState.Valid || !string.Equals(info.Organization ?? info.Signer, publisher, StringComparison.Ordinal))
            {
                findings.Add(new IntegrityFinding(IntegrityKinds.Signature, relative));
            }
        }

        return true;
    }

    /// <summary>CrioFire's own programs (the .NET runtime beside them is signed by Microsoft).</summary>
    internal static bool IsOwnProgram(string relative)
    {
        var name = Path.GetFileName(relative);
        return name.StartsWith("criofire", StringComparison.OrdinalIgnoreCase)
            && (name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) || name.EndsWith(".dll", StringComparison.OrdinalIgnoreCase));
    }

    private static bool IsManifest(string relative) => string.Equals(relative, IntegrityManifest.FileName, StringComparison.OrdinalIgnoreCase);

    private static string Hash(string path)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        return Convert.ToHexStringLower(SHA256.HashData(stream));
    }
}

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase, PropertyNameCaseInsensitive = true, WriteIndented = true)]
[JsonSerializable(typeof(IntegrityManifest))]
internal sealed partial class IntegrityJson : JsonSerializerContext
{
}
