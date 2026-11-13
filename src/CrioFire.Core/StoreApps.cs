namespace CrioFire.Core;

/// <summary>
/// Microsoft Store (packaged) apps. They live in a folder named after the exact version
/// (C:\Program Files\WindowsApps\Microsoft.WindowsTerminal_1.21.2361.0_x64__8wekyb3d8bbwe), so a
/// rule by path would stop matching at the next update. CrioFire keys their rules by the package
/// family ("pkg:Microsoft.WindowsTerminal_8wekyb3d8bbwe"), which stays the same across updates.
/// </summary>
public static class StoreApps
{
    /// <summary>The prefix of a package rule's program: <c>pkg:</c> + package family name.</summary>
    public const string Prefix = "pkg:";

    private const string Folder = "WindowsApps";
    private const int MaxPrograms = 256;

    public static bool IsPackage(string? app) => app is not null && app.StartsWith(Prefix, StringComparison.OrdinalIgnoreCase);

    public static string Key(string family) => Prefix + family;

    public static string Family(string key) => IsPackage(key) ? key[Prefix.Length..] : key;

    /// <summary>
    /// The package family of a program inside a WindowsApps folder, or null for anything else.
    /// Package folders are named Name_Version_Architecture_ResourceId_PublisherId; the family is
    /// Name_PublisherId.
    /// </summary>
    public static string? FamilyFromPath(string? path)
    {
        if (string.IsNullOrEmpty(path))
        {
            return null;
        }

        var parts = path.Split('\\', '/');
        for (var i = 0; i < parts.Length - 2; i++)
        {
            if (parts[i].Equals(Folder, StringComparison.OrdinalIgnoreCase) && FamilyFromFolderName(parts[i + 1]) is { } family)
            {
                return family;
            }
        }

        return null;
    }

    /// <summary>The family of a package folder name, or null when it is not one.</summary>
    public static string? FamilyFromFolderName(string name)
    {
        var parts = name.Split('_');
        if (parts.Length != 5 || parts[0].Length == 0 || parts[4].Length == 0 || !Version.TryParse(parts[1], out _))
        {
            return null;
        }

        return parts[0] + "_" + parts[4];
    }

    /// <summary>The WindowsApps folder a program lives in (C:\Program Files\WindowsApps), or null.</summary>
    public static string? RootFromPath(string? path)
    {
        if (string.IsNullOrEmpty(path))
        {
            return null;
        }

        var at = path.IndexOf("\\" + Folder + "\\", StringComparison.OrdinalIgnoreCase);
        return at < 0 ? null : path[..(at + Folder.Length + 1)];
    }

    /// <summary>"Microsoft.WindowsTerminal (Store app)".</summary>
    public static string DisplayName(string key)
    {
        var family = Family(key);
        var underscore = family.LastIndexOf('_');
        return (underscore > 0 ? family[..underscore] : family) + " (Store app)";
    }

    public static string DefaultRoot =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), Folder);

    /// <summary>
    /// The installed folders of a package family (main packages only, not resource packages),
    /// every version present. Empty when the folder cannot be read (it needs SYSTEM or
    /// administrator rights).
    /// </summary>
    public static IReadOnlyList<string> InstallFolders(string family, IEnumerable<string>? roots = null)
    {
        var name = family[..Math.Max(0, family.LastIndexOf('_'))];
        if (name.Length == 0)
        {
            return [];
        }

        var found = new List<string>();
        foreach (var root in (roots ?? [DefaultRoot]).Distinct(StringComparer.OrdinalIgnoreCase))
        {
            try
            {
                if (!Directory.Exists(root))
                {
                    continue;
                }

                foreach (var dir in Directory.EnumerateDirectories(root, name + "_*"))
                {
                    var folder = Path.GetFileName(dir);
                    var parts = folder.Split('_');
                    if (string.Equals(FamilyFromFolderName(folder), family, StringComparison.OrdinalIgnoreCase) && parts[3].Length == 0)
                    {
                        found.Add(dir);
                    }
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                // Not readable from here; the package SID filter still covers sandboxed apps.
            }
        }

        found.Sort(StringComparer.OrdinalIgnoreCase);
        return found;
    }

    /// <summary>The programs (.exe) in a package family's installed folders.</summary>
    public static IReadOnlyList<string> Programs(string family, IEnumerable<string>? roots = null)
    {
        var options = new EnumerationOptions { RecurseSubdirectories = true, IgnoreInaccessible = true };
        var programs = new List<string>();
        foreach (var folder in InstallFolders(family, roots))
        {
            try
            {
                programs.AddRange(Directory.EnumerateFiles(folder, "*.exe", options).Take(MaxPrograms - programs.Count));
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                // Skip a folder that disappeared mid-update.
            }

            if (programs.Count >= MaxPrograms)
            {
                break;
            }
        }

        return programs;
    }

    /// <summary>A fingerprint of what is installed, to notice updates: the folder names.</summary>
    public static string InstalledSignature(string family, IEnumerable<string>? roots = null) =>
        string.Join('|', InstallFolders(family, roots).Select(Path.GetFileName));

    /// <summary>
    /// Keeps package rules current: when a Store app was updated (a new version folder), its rules
    /// are written again so they cover the new program files. Call regularly; <paramref name="seen"/>
    /// remembers what was installed last time (empty at service start, so every rule is renewed once).
    /// Returns the packages whose rules were renewed.
    /// </summary>
    public static IReadOnlyList<string> Refresh(WfpEngine engine, IDictionary<string, string> seen)
    {
        ArgumentNullException.ThrowIfNull(engine);
        ArgumentNullException.ThrowIfNull(seen);
        var renewed = new List<string>();
        var rules = engine.ListFilters()
            .Where(f => f.Kind == FilterKind.AppRule && f.Rule is not null && IsPackage(f.Rule.AppPath))
            .GroupBy(f => (Key: f.Rule!.AppPath.ToLowerInvariant(), f.Managed));
        foreach (var package in rules)
        {
            var key = package.First().Rule!.AppPath;
            var seenKey = (package.Key.Managed ? "managed|" : string.Empty) + key;
            var signature = InstalledSignature(Family(key));
            if (seen.TryGetValue(seenKey, out var before) && before == signature)
            {
                continue;
            }

            foreach (var (action, direction) in package.Select(f => (f.Rule!.Action, f.Rule.Direction)).Distinct())
            {
                if (package.Key.Managed)
                {
                    engine.Managed(() => engine.SetAppRule(key, action, direction));   // an organization rule stays one
                }
                else
                {
                    engine.SetAppRule(key, action, direction);
                }
            }

            seen[seenKey] = signature;
            renewed.Add(key);
        }

        return renewed;
    }
}
