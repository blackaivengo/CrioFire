using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;

namespace CrioFire.Core;

/// <summary>
/// Writes a file only SYSTEM and administrators may read (this PC's secret for its server, the
/// license key). The file is created with those permissions, not given them afterwards, so there
/// is no moment at which another account could read it.
/// </summary>
public static class SecretFile
{
    public static void Write(string path, string text)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        ArgumentNullException.ThrowIfNull(text);
        var full = Path.GetFullPath(path);
        Directory.CreateDirectory(Path.GetDirectoryName(full)!);
        var temp = full + ".tmp";
        File.Delete(temp);
        if (OperatingSystem.IsWindows())
        {
            var security = new FileSecurity();
            security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            security.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), FileSystemRights.FullControl, AccessControlType.Allow));
            security.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), FileSystemRights.FullControl, AccessControlType.Allow));
            using var stream = new FileInfo(temp).Create(FileMode.CreateNew, FileSystemRights.Write, FileShare.None, 4096, FileOptions.None, security);
            stream.Write(new UTF8Encoding(false).GetBytes(text));
        }
        else
        {
            File.WriteAllText(temp, text);
        }

        File.Move(temp, full, overwrite: true);
    }
}
