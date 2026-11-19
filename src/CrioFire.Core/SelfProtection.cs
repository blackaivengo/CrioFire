using System.ComponentModel;
using System.Globalization;
using System.Runtime.InteropServices;
using CrioFire.Core.Api;
using Microsoft.Win32;

namespace CrioFire.Core;

/// <summary>
/// CrioFire looking after itself: are its files the installed ones, did the service end without
/// being asked to, and the way for an administrator to stop it when the service is locked.
/// One instance is shared by the service's API and its protection loop.
/// </summary>
public sealed class SelfProtection(string folder, Func<string, SignatureInfo>? signature = null, string? markerPath = null)
{
    private readonly Lock _gate = new();
    private IntegrityInfo? _latest;

    public static string DefaultMarkerPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "criofire", "running.txt");

    /// <summary>The folder that is checked: where the service runs from.</summary>
    public string Folder { get; } = folder;

    /// <summary>The last check, or null before the first one.</summary>
    public IntegrityInfo? Latest
    {
        get
        {
            lock (_gate)
            {
                return _latest;
            }
        }
    }

    /// <summary>When the service last ran before it ended without a clean stop (killed, crashed, power lost); null if it stopped cleanly.</summary>
    public DateTime? UnexpectedStopUtc { get; private set; }

    /// <summary>Set by the service: stops it cleanly. Null when there is no service to stop (the command line working directly).</summary>
    public Action? StopRequested { get; set; }

    /// <summary>Set by the service: tamper protection was switched, apply the service lock now.</summary>
    public Action<bool>? ProtectionChanged { get; set; }

    /// <summary>Checks every file now (reads them all: a second or two).</summary>
    public IntegrityInfo Check(DateTime nowUtc)
    {
        var result = FileIntegrity.Verify(Folder, FileIntegrity.Load(Folder), nowUtc, signature);
        lock (_gate)
        {
            _latest = result;
        }

        return result;
    }

    /// <summary>
    /// Service start: a marker left by the previous run means that run did not stop cleanly.
    /// Returns when it was last alive, and starts this run's marker.
    /// </summary>
    public DateTime? NoteStart(DateTime nowUtc)
    {
        if (markerPath is null)
        {
            return null;
        }

        try
        {
            if (File.Exists(markerPath))
            {
                UnexpectedStopUtc = DateTime.TryParse(File.ReadAllText(markerPath).Trim(), CultureInfo.InvariantCulture,
                    DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out var last)
                    ? last
                    : File.GetLastWriteTimeUtc(markerPath);
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Unknown: say nothing rather than guess.
        }

        Heartbeat(nowUtc);
        return UnexpectedStopUtc;
    }

    /// <summary>The service is alive (written every minute).</summary>
    public void Heartbeat(DateTime nowUtc)
    {
        if (markerPath is null)
        {
            return;
        }

        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(markerPath))!);
            File.WriteAllText(markerPath, nowUtc.ToString("O", CultureInfo.InvariantCulture));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Best effort.
        }
    }

    /// <summary>The service is stopping because it was asked to.</summary>
    public void NoteCleanStop()
    {
        if (markerPath is null)
        {
            return;
        }

        try
        {
            File.Delete(markerPath);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // The next start then reports an unexpected stop; better than hiding one.
        }
    }
}

/// <summary>
/// Windows-side hardening of the criofire service: who may stop or reconfigure it, and who may
/// end its process. With the lock on, administrators can still start the service and read its
/// state, but stopping, pausing, reconfiguring or deleting it is left to SYSTEM (Windows
/// Installer for upgrades and uninstalls, and the service itself when an elevated CrioFire asks).
/// </summary>
public static partial class ServiceGuard
{
    public const string ServiceName = "criofire";

    /// <summary>The service's permissions as Windows sets them for a new service.</summary>
    public const string UnlockedSddl = "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)";

    /// <summary>Locked: administrators keep query, start (RP) and read; stop (WP), pause (DT), change (DC), delete (SD) and permission changes (WD, WO) are SYSTEM's.</summary>
    public const string LockedSddl = "D:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCLCSWRPLOCRRC;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)";

    /// <summary>
    /// The service process: SYSTEM everything; administrators may look (query, wait, read
    /// permissions) but not end it, write to its memory or start threads in it.
    /// </summary>
    public const string ProcessSddl = "D:P(A;;GA;;;SY)(A;;0x121400;;;BA)";

    private const uint DaclSecurityInformation = 4;
    private const uint ScManagerConnect = 0x0001;
    private const uint ServiceChangeConfig = 0x0002;
    private const uint ReadControl = 0x20000;
    private const uint WriteDac = 0x40000;
    private const uint ServiceNoChange = 0xFFFFFFFF;
    private const uint ServiceAutoStart = 2;

    /// <summary>Applies <see cref="ProcessSddl"/> to this process.</summary>
    public static void HardenProcess()
    {
        var descriptor = Descriptor(ProcessSddl);
        try
        {
            if (!SetKernelObjectSecurity(GetCurrentProcess(), DaclSecurityInformation, descriptor))
            {
                throw new Win32Exception(Marshal.GetLastPInvokeError());
            }
        }
        finally
        {
            LocalFree(descriptor);
        }
    }

    /// <summary>Locks or unlocks the service's permissions. Needs to run as SYSTEM once locked.</summary>
    public static void SetServiceLock(bool locked, string service = ServiceName)
    {
        var descriptor = Descriptor(locked ? LockedSddl : UnlockedSddl);
        try
        {
            WithService(service, ReadControl | WriteDac, handle =>
            {
                if (!SetServiceObjectSecurity(handle, DaclSecurityInformation, descriptor))
                {
                    throw new Win32Exception(Marshal.GetLastPInvokeError());
                }
            });
        }
        finally
        {
            LocalFree(descriptor);
        }
    }

    /// <summary>
    /// Puts the service back to starting with Windows if something disabled it. Returns true
    /// when it had to.
    /// </summary>
    public static bool EnsureAutomaticStart(string service = ServiceName)
    {
        using var key = Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\{service}");
        if (key?.GetValue("Start") is not int start || start == (int)ServiceAutoStart)
        {
            return false;
        }

        WithService(service, ServiceChangeConfig, handle =>
        {
            if (!ChangeServiceConfigW(handle, ServiceNoChange, ServiceAutoStart, ServiceNoChange, null, null, IntPtr.Zero, null, null, null, null))
            {
                throw new Win32Exception(Marshal.GetLastPInvokeError());
            }
        });
        return true;
    }

    private static void WithService(string service, uint access, Action<IntPtr> action)
    {
        var manager = OpenSCManagerW(null, null, ScManagerConnect);
        if (manager == IntPtr.Zero)
        {
            throw new Win32Exception(Marshal.GetLastPInvokeError());
        }

        try
        {
            var handle = OpenServiceW(manager, service, access);
            if (handle == IntPtr.Zero)
            {
                throw new Win32Exception(Marshal.GetLastPInvokeError());
            }

            try
            {
                action(handle);
            }
            finally
            {
                CloseServiceHandle(handle);
            }
        }
        finally
        {
            CloseServiceHandle(manager);
        }
    }

    private static IntPtr Descriptor(string sddl)
    {
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, out var descriptor, out _))
        {
            throw new Win32Exception(Marshal.GetLastPInvokeError());
        }

        return descriptor;
    }

    [LibraryImport("advapi32.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool ConvertStringSecurityDescriptorToSecurityDescriptorW(string sddl, uint revision, out IntPtr descriptor, out uint size);

    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool SetKernelObjectSecurity(IntPtr handle, uint information, IntPtr descriptor);

    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool SetServiceObjectSecurity(IntPtr service, uint information, IntPtr descriptor);

    [LibraryImport("advapi32.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    private static partial IntPtr OpenSCManagerW(string? machine, string? database, uint access);

    [LibraryImport("advapi32.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    private static partial IntPtr OpenServiceW(IntPtr manager, string service, uint access);

    [LibraryImport("advapi32.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool ChangeServiceConfigW(IntPtr service, uint type, uint start, uint errorControl, string? binaryPath, string? loadOrderGroup,
        IntPtr tagId, string? dependencies, string? startName, string? password, string? displayName);

    [LibraryImport("advapi32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CloseServiceHandle(IntPtr handle);

    [LibraryImport("kernel32.dll")]
    private static partial IntPtr GetCurrentProcess();

    [LibraryImport("kernel32.dll")]
    private static partial IntPtr LocalFree(IntPtr memory);
}
