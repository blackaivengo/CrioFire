using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using System.Text.Json.Nodes;
using CrioFire.Core.Management;

namespace CrioFire.Server;

/// <summary>
/// What the installer (or an administrator setting the server up by hand) runs once:
/// the port, the Windows Firewall rule that lets PCs reach the server, a data folder only SYSTEM
/// and administrators can read, and the server's certificate.
/// </summary>
internal static class ServerSetup
{
    public const string FirewallRuleName = "CrioFire Server";

    /// <summary>criofire-server setup [--port N]</summary>
    public static int Setup(string folder, string[] args)
    {
        var settings = ServerSettings.Load(folder);
        var port = settings.Port;
        for (var i = 0; i < args.Length; i++)
        {
            if (args[i] == "--port" && i + 1 < args.Length)
            {
                port = ParsePort(args[++i]);
            }
            else
            {
                throw new ArgumentException($"Unknown option {args[i]}.");
            }
        }

        Directory.CreateDirectory(folder);
        SecureFolder(folder);
        ServerSettings.SavePort(folder, port);
        var certificate = ServerCertificate.LoadOrCreate(folder, DateTime.UtcNow);
        Console.WriteLine($"Data folder: {folder}" + (OperatingSystem.IsWindows() ? " (SYSTEM and administrators only)" : string.Empty));
        Console.WriteLine($"Port: {port}");
        Console.WriteLine($"Certificate fingerprint: {Fingerprints.Of(certificate)}");

        if (OperatingSystem.IsWindows())
        {
            var exe = Environment.ProcessPath ?? throw new IOException("Cannot tell where criofire-server.exe is.");
            Netsh($"advfirewall firewall delete rule name=\"{FirewallRuleName}\"", mayFail: true);
            Netsh($"advfirewall firewall add rule name=\"{FirewallRuleName}\" dir=in action=allow protocol=TCP localport={port.ToString(CultureInfo.InvariantCulture)} program=\"{exe}\" profile=any enable=yes description=\"Lets PCs and administrators reach the CrioFire Server.\"", mayFail: false);
            Console.WriteLine($"Windows Firewall: allows TCP {port} in to criofire-server.exe.");
        }

        return 0;
    }

    /// <summary>criofire-server uninstall: removes the firewall rule. The data folder stays (enrolled PCs, policies, administrators).</summary>
    public static int Uninstall()
    {
        if (OperatingSystem.IsWindows())
        {
            Netsh($"advfirewall firewall delete rule name=\"{FirewallRuleName}\"", mayFail: true);
        }

        Console.WriteLine("Removed the Windows Firewall rule. The data folder is kept; delete it to forget enrolled PCs, policies and administrators.");
        return 0;
    }

    public static int ParsePort(string text) =>
        int.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out var port) && port is > 0 and < 65536
            ? port
            : throw new ArgumentException($"'{text}' is not a port number (1 to 65535).");

    /// <summary>
    /// Only SYSTEM and administrators may read the data folder: it holds the certificate's private
    /// key, administrators' password hashes and the console's cookie keys. %ProgramData% would
    /// otherwise let every user read it.
    /// </summary>
    public static void SecureFolder(string folder)
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        foreach (var sid in new[] { WellKnownSidType.LocalSystemSid, WellKnownSidType.BuiltinAdministratorsSid })
        {
            security.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(sid, null), FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        }

        new DirectoryInfo(folder).SetAccessControl(security);
    }

    /// <summary>True for a request from this machine itself.</summary>
    public static bool IsLocal(IPAddress? address) => address is not null && IPAddress.IsLoopback(address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address);

    private static void Netsh(string arguments, bool mayFail)
    {
        using var process = Process.Start(new ProcessStartInfo("netsh.exe", arguments)
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        }) ?? throw new IOException("Could not start netsh.");
        var output = process.StandardOutput.ReadToEnd() + process.StandardError.ReadToEnd();
        process.WaitForExit();
        if (process.ExitCode != 0 && !mayFail)
        {
            throw new IOException($"Could not add the Windows Firewall rule: {output.Trim()}");
        }
    }
}

internal static class ServerSettingsFile
{
    private static readonly JsonSerializerOptions Indented = new() { WriteIndented = true };

    /// <summary>Sets one value in settings.json and keeps the others.</summary>
    public static void Set(string folder, string name, JsonNode? value)
    {
        var path = Path.Combine(folder, "settings.json");
        JsonObject root;
        try
        {
            root = File.Exists(path) ? JsonNode.Parse(File.ReadAllText(path)) as JsonObject ?? [] : [];
        }
        catch (JsonException)
        {
            root = [];
        }

        root[name] = value;
        Directory.CreateDirectory(folder);
        File.WriteAllText(path + ".tmp", root.ToJsonString(Indented));
        File.Move(path + ".tmp", path, overwrite: true);
    }
}
