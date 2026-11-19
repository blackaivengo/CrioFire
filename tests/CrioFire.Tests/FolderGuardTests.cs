using System.Security.AccessControl;
using System.Security.Principal;
using CrioFire.Core;

namespace CrioFire.Tests;

public class FolderGuardTests
{
    [Fact]
    public void OnlySystemAdministratorsAndWindowsInstallerAreTrustedOwners()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        Assert.True(FolderGuard.IsTrusted(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null)));
        Assert.True(FolderGuard.IsTrusted(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null)));
        Assert.False(FolderGuard.IsTrusted(new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null)));
        Assert.False(FolderGuard.IsTrusted(new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null)));
        Assert.False(FolderGuard.IsTrusted(new SecurityIdentifier("S-1-5-21-1111111111-2222222222-3333333333-1001")));
        Assert.False(FolderGuard.IsTrusted(null));
    }

    [Fact]
    public void ASecuredFolderBelongsToAdministratorsAndNobodyElseMayWrite()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        using (var identity = WindowsIdentity.GetCurrent())
        {
            if (!new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
            {
                return;   // taking a folder over needs an administrator (CI runs as one)
            }
        }

        var folder = Path.Combine(Path.GetTempPath(), "criofire-guard-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Path.Combine(folder, "sub"));
        File.WriteAllText(Path.Combine(folder, "sub", "settings.json"), "{}");
        try
        {
            // Open to everyone, as a folder outside Program Files can be.
            var open = new DirectorySecurity();
            open.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null), FileSystemRights.Modify,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
            new DirectoryInfo(folder).SetAccessControl(open);

            FolderGuard.Secure(folder, FolderAccess.ProgramFolder, setAsideForeignFiles: false);

            foreach (var path in new[] { folder, Path.Combine(folder, "sub") })
            {
                var security = new DirectoryInfo(path).GetAccessControl();
                Assert.True(FolderGuard.IsTrusted(security.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier));
                AssertOnlyAdministratorsWrite(security.GetAccessRules(true, true, typeof(SecurityIdentifier)));
            }

            var file = new FileInfo(Path.Combine(folder, "sub", "settings.json")).GetAccessControl();
            AssertOnlyAdministratorsWrite(file.GetAccessRules(true, true, typeof(SecurityIdentifier)));
            Assert.True(new DirectoryInfo(folder).GetAccessControl().AreAccessRulesProtected);
            Assert.Equal("{}", File.ReadAllText(Path.Combine(folder, "sub", "settings.json")));   // nothing was moved
        }
        finally
        {
            Directory.Delete(folder, recursive: true);
        }
    }

    private static void AssertOnlyAdministratorsWrite(AuthorizationRuleCollection rules)
    {
        const FileSystemRights writing = FileSystemRights.WriteData | FileSystemRights.AppendData | FileSystemRights.Delete
            | FileSystemRights.DeleteSubdirectoriesAndFiles | FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership
            | FileSystemRights.WriteAttributes | FileSystemRights.WriteExtendedAttributes;
        foreach (FileSystemAccessRule rule in rules)
        {
            if (rule.AccessControlType == AccessControlType.Allow && (rule.FileSystemRights & writing) != 0)
            {
                Assert.True(FolderGuard.IsTrusted(rule.IdentityReference as SecurityIdentifier), $"{rule.IdentityReference} may write.");
            }
        }
    }
}
