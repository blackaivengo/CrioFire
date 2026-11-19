using System.Security.AccessControl;
using System.Security.Principal;

namespace CrioFire.Core;

/// <summary>Who may read a folder CrioFire relies on. Only SYSTEM and administrators may ever write.</summary>
public enum FolderAccess
{
    /// <summary>SYSTEM and administrators only (the server's keys and password hashes).</summary>
    AdministratorsOnly,

    /// <summary>Users may read (the firewall's data folder: the app shows what is in it).</summary>
    UsersRead,

    /// <summary>Users and app packages may read and run (a program folder).</summary>
    ProgramFolder,
}

/// <summary>What <see cref="FolderGuard.Secure"/> had to put right.</summary>
/// <param name="OwnersReset">Files and folders that belonged to an ordinary account and now belong to the administrators.</param>
/// <param name="SetAside">Files of an ordinary account, moved to the folder <see cref="FolderGuard.SetAsideName"/>.</param>
/// <param name="LinksRemoved">Links (junctions, symbolic links) removed: they could lead CrioFire's files elsewhere.</param>
public sealed record FolderRepair(int OwnersReset, IReadOnlyList<string> SetAside, IReadOnlyList<string> LinksRemoved)
{
    public bool Any => OwnersReset > 0 || SetAside.Count > 0 || LinksRemoved.Count > 0;
}

/// <summary>
/// Makes a folder CrioFire relies on belong to the administrators, writable by them and SYSTEM
/// alone. Setting permissions is not enough: an ordinary user can create %ProgramData%\criofire
/// (or own the folder CrioFire is installed to) before CrioFire is installed, and the owner of a
/// folder can always change its permissions back. So the owner is set too, links are removed, and
/// anything an ordinary account put there is taken over, and for a data folder set aside so the
/// service never reads settings somebody else wrote.
/// </summary>
public static partial class FolderGuard
{
    /// <summary>Where files that an ordinary account put in a data folder are moved.</summary>
    public const string SetAsideName = "not-from-criofire";

    private const string TrustedInstaller = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";
    private const string AllApplicationPackages = "S-1-15-2-1";

    /// <summary>
    /// Secures <paramref name="folder"/> (creating it if needed) and everything in it.
    /// <paramref name="setAsideForeignFiles"/>: move files that belonged to an ordinary account
    /// out of the way. A data folder that itself belonged to an ordinary account gets this
    /// whatever is asked. In a program folder such files are only taken over, and the check of
    /// CrioFire's own files reports them.
    /// </summary>
    public static FolderRepair Secure(string folder, FolderAccess access, bool setAsideForeignFiles)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(folder);
        if (!OperatingSystem.IsWindows())
        {
            return new FolderRepair(0, [], []);
        }

        // Lets an administrator or SYSTEM take a file over even when its owner has shut them out.
        EnablePrivilege("SeTakeOwnershipPrivilege");
        var root = Path.TrimEndingDirectorySeparator(Path.GetFullPath(folder));
        var links = new List<string>();
        var aside = new List<string>();
        var owners = 0;

        // A link in the folder's place would send everything CrioFire writes somewhere else.
        var info = new DirectoryInfo(root);
        if (info.Exists && info.Attributes.HasFlag(FileAttributes.ReparsePoint))
        {
            info.Delete();   // the link itself, not what it points to
            links.Add(root);
        }

        Directory.CreateDirectory(root);
        info = new DirectoryInfo(root);
        if (!IsTrusted(Owner(info)))
        {
            // The folder itself was somebody else's: nothing in it can be taken for CrioFire's.
            owners++;
            setAsideForeignFiles |= access != FolderAccess.ProgramFolder;
        }

        // The owner first, in a step of its own: only the owner is sure to be let change the permissions.
        var administrators = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        SetOwner(info, administrators);
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        const InheritanceFlags inherit = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
        security.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(administrators, FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
        if (access != FolderAccess.AdministratorsOnly)
        {
            security.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null), FileSystemRights.ReadAndExecute, inherit, PropagationFlags.None, AccessControlType.Allow));
        }

        if (access == FolderAccess.ProgramFolder)
        {
            security.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(AllApplicationPackages), FileSystemRights.ReadAndExecute, inherit, PropagationFlags.None, AccessControlType.Allow));
        }

        info.SetAccessControl(security);

        var asideFolder = Path.Combine(root, SetAsideName);
        var pending = new Stack<string>();
        pending.Push(root);
        while (pending.Count > 0)
        {
            var current = pending.Pop();
            IEnumerable<FileSystemInfo> entries;
            try
            {
                entries = new DirectoryInfo(current).EnumerateFileSystemInfos().ToList();
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var entry in entries)
            {
                try
                {
                    if (entry.Attributes.HasFlag(FileAttributes.ReparsePoint))
                    {
                        // Never followed. One an ordinary account made is removed: changing its
                        // permissions would change those of whatever it points to.
                        if (!IsTrusted(Owner(entry)))
                        {
                            entry.Delete();
                            links.Add(entry.FullName);
                        }

                        continue;
                    }

                    var foreign = !IsTrusted(Owner(entry));
                    if (foreign)
                    {
                        TakeOver(entry, administrators);
                        owners++;
                    }

                    if (entry is DirectoryInfo)
                    {
                        if (!string.Equals(entry.FullName, asideFolder, StringComparison.OrdinalIgnoreCase))
                        {
                            pending.Push(entry.FullName);
                        }
                    }
                    else if (foreign && setAsideForeignFiles)
                    {
                        Directory.CreateDirectory(asideFolder);
                        var target = Path.Combine(asideFolder, $"{DateTime.UtcNow:yyyyMMdd-HHmmss}-{Path.GetRelativePath(root, entry.FullName).Replace(Path.DirectorySeparatorChar, '_')}");
                        File.Move(entry.FullName, target, overwrite: true);
                        aside.Add(Path.GetRelativePath(root, entry.FullName));
                    }
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException or IdentityNotMappedException)
                {
                    // In use or already gone: the folder's own permissions still keep others out.
                }
            }
        }

        return new FolderRepair(owners, aside, links);
    }

    /// <summary>SYSTEM, the administrators and Windows' own installer: the accounts whose files are CrioFire's or an administrator's.</summary>
    public static bool IsTrusted(SecurityIdentifier? owner) =>
        owner is not null
        && (owner.IsWellKnown(WellKnownSidType.LocalSystemSid)
            || owner.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid)
            || string.Equals(owner.Value, TrustedInstaller, StringComparison.Ordinal));

    /// <summary>The entry's owner; null when it cannot even be read (then it is nobody CrioFire trusts).</summary>
    private static SecurityIdentifier? Owner(FileSystemInfo entry)
    {
        if (!OperatingSystem.IsWindows())
        {
            return null;
        }

        try
        {
            FileSystemSecurity security = entry is DirectoryInfo
                ? new DirectorySecurity(entry.FullName, AccessControlSections.Owner)
                : new FileSecurity(entry.FullName, AccessControlSections.Owner);
            return security.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or InvalidOperationException)
        {
            return null;
        }
    }

    private static void SetOwner(FileSystemInfo entry, SecurityIdentifier owner)
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        if (entry is DirectoryInfo directory)
        {
            var security = new DirectorySecurity();
            security.SetOwner(owner);
            directory.SetAccessControl(security);
        }
        else
        {
            var security = new FileSecurity();
            security.SetOwner(owner);
            ((FileInfo)entry).SetAccessControl(security);
        }
    }

    /// <summary>Gives the entry to the administrators, then drops every permission of its own: it inherits the folder's.</summary>
    private static void TakeOver(FileSystemInfo entry, SecurityIdentifier administrators)
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        SetOwner(entry, administrators);
        if (entry is DirectoryInfo directory)
        {
            var security = new DirectorySecurity();
            security.SetAccessRuleProtection(isProtected: false, preserveInheritance: false);
            directory.SetAccessControl(security);
        }
        else
        {
            var security = new FileSecurity();
            security.SetAccessRuleProtection(isProtected: false, preserveInheritance: false);
            ((FileInfo)entry).SetAccessControl(security);
        }
    }

    /// <summary>Turns on a privilege this process holds but Windows keeps switched off until asked. Without it, nothing changes.</summary>
    private static unsafe void EnablePrivilege(string name)
    {
        const uint adjustPrivileges = 0x20, query = 0x8, enabled = 0x2;
        if (!OpenProcessToken(GetCurrentProcess(), adjustPrivileges | query, out var token))
        {
            return;
        }

        try
        {
            var privileges = new TokenPrivileges { Count = 1, Attributes = enabled };
            if (LookupPrivilegeValueW(null, name, out privileges.Luid))
            {
                _ = AdjustTokenPrivileges(token, disableAll: false, &privileges, 0, IntPtr.Zero, IntPtr.Zero);
            }
        }
        finally
        {
            CloseHandle(token);
        }
    }

    [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential, Pack = 4)]
    private struct TokenPrivileges
    {
        public uint Count;
        public long Luid;
        public uint Attributes;
    }

    [System.Runtime.InteropServices.LibraryImport("kernel32.dll")]
    private static partial IntPtr GetCurrentProcess();

    [System.Runtime.InteropServices.LibraryImport("kernel32.dll")]
    [return: System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.Bool)]
    private static partial bool CloseHandle(IntPtr handle);

    [System.Runtime.InteropServices.LibraryImport("advapi32.dll", SetLastError = true)]
    [return: System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.Bool)]
    private static partial bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);

    [System.Runtime.InteropServices.LibraryImport("advapi32.dll", SetLastError = true, StringMarshalling = System.Runtime.InteropServices.StringMarshalling.Utf16)]
    [return: System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.Bool)]
    private static partial bool LookupPrivilegeValueW(string? system, string name, out long luid);

    [System.Runtime.InteropServices.LibraryImport("advapi32.dll", SetLastError = true)]
    [return: System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.Bool)]
    private static unsafe partial bool AdjustTokenPrivileges(IntPtr token, [System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.Bool)] bool disableAll,
        TokenPrivileges* newState, uint length, IntPtr previous, IntPtr returnLength);
}
