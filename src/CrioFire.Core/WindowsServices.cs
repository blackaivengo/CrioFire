using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using CrioFire.Core.Interop;

namespace CrioFire.Core;

/// <summary>Programs that are not files: the Windows kernel's own traffic.</summary>
public static class KnownApps
{
    /// <summary>The app ID WFP gives kernel-mode traffic (SMB, NetBIOS, ICMP replies...). Also PID 4.</summary>
    public const string Kernel = "System";

    /// <summary>CrioFire's own service, which may always connect (to a company's CrioFire Server).</summary>
    public const string CrioFireService = "criofire-svc.exe";

    /// <summary>The name of the built-in permit for <see cref="CrioFireService"/>.</summary>
    public const string CrioFireServiceRule = "criofire";

    public static bool IsKernel(string? app) => string.Equals(app?.Trim(), Kernel, StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// A rule's program as stored: "System" for the kernel, "pkg:family" for a Microsoft Store app
    /// (so the rule survives its updates), otherwise the full path.
    /// </summary>
    public static string Normalize(string app)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(app);
        if (IsKernel(app))
        {
            return Kernel;
        }

        if (StoreApps.IsPackage(app))
        {
            return app.Trim();
        }

        var full = Path.GetFullPath(app);
        return StoreApps.FamilyFromPath(full) is { } family ? StoreApps.Key(family) : full;
    }

    /// <summary>
    /// What a rule for this program is keyed by, without touching the file system: like
    /// <see cref="Normalize"/> for paths that are already full (from connections and events).
    /// </summary>
    public static string RuleKey(string app)
    {
        if (IsKernel(app))
        {
            return Kernel;
        }

        return StoreApps.FamilyFromPath(app) is { } family ? StoreApps.Key(family) : app;
    }

    /// <summary>True when a rule for <paramref name="ruleApp"/> applies to the program <paramref name="app"/>.</summary>
    public static bool SameApp(string? ruleApp, string? app) =>
        ruleApp is not null && app is not null && string.Equals(RuleKey(ruleApp), RuleKey(app), StringComparison.OrdinalIgnoreCase);

    /// <summary>True for svchost.exe, the shared host of most Windows services.</summary>
    public static bool IsServiceHost(string? app) =>
        app is not null && app.EndsWith("svchost.exe", StringComparison.OrdinalIgnoreCase)
        && (app.Length == "svchost.exe".Length || app[app.Length - "svchost.exe".Length - 1] is '\\' or '/');

    /// <summary>A short name for lists: "Windows kernel (System)", or the file name.</summary>
    public static string DisplayName(string? app)
    {
        if (string.IsNullOrEmpty(app))
        {
            return "(unknown program)";
        }

        if (IsKernel(app))
        {
            return "Windows kernel (System)";
        }

        if (StoreApps.IsPackage(app))
        {
            return StoreApps.DisplayName(app);
        }

        var slash = app.LastIndexOfAny(['\\', '/']);
        return slash >= 0 ? app[(slash + 1)..] : app;
    }
}

/// <summary>
/// A rule for one Windows service, matched by its service SID (NT SERVICE\name), so a single
/// service inside a shared svchost.exe can be allowed or blocked. Format:
/// <c>criofire:v1|svc|block|out|Dnscache</c>.
/// </summary>
public sealed record ServiceRule(RuleAction Action, TrafficDirection Direction, string ServiceName, NetworkProfiles Networks = NetworkProfiles.Any)
{
    public string Format() =>
        string.Join('|', RuleDescription.Prefix, "svc", NetworkScope.ActionField(Action, Networks), RuleDescription.DirectionText(Direction), ServiceName);

    public static bool TryParse(string? text, out ServiceRule? rule)
    {
        rule = null;
        var parts = text?.Split('|') ?? [];
        if (parts.Length != 5 || parts[0] != RuleDescription.Prefix || parts[1] != "svc" || !IsValidName(parts[4]))
        {
            return false;
        }

        TrafficDirection? direction = parts[3] switch
        {
            "out" => TrafficDirection.Outbound,
            "in" => TrafficDirection.Inbound,
            "both" => TrafficDirection.Both,
            _ => null,
        };
        if (!NetworkScope.TryParseActionField(parts[2], out var action, out var networks) || direction is null)
        {
            return false;
        }

        rule = new ServiceRule(action, direction.Value, parts[4], networks);
        return true;
    }

    /// <summary>Service key names: up to 256 characters, no slashes (Windows), and no '|' (our format).</summary>
    public static bool IsValidName(string? name) =>
        !string.IsNullOrWhiteSpace(name) && name.Length <= 256 && name.Trim() == name
        && name.IndexOfAny(['/', '\\', '|', '(', ')', ';']) < 0
        && !name.Any(char.IsControl);
}

/// <summary>Computes service SIDs. Pure logic, unit-tested.</summary>
public static class ServiceSid
{
    /// <summary>
    /// S-1-5-80- followed by the SHA-1 of the upper-case service name (UTF-16LE) as five
    /// little-endian 32-bit numbers: the SID "sc showsid" prints.
    /// </summary>
    public static string For(string serviceName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(serviceName);
#pragma warning disable CA5350 // Not for security: Windows defines service SIDs with SHA-1.
        var hash = SHA1.HashData(Encoding.Unicode.GetBytes(serviceName.ToUpperInvariant()));
#pragma warning restore CA5350
        var parts = new uint[5];
        for (var i = 0; i < 5; i++)
        {
            parts[i] = BitConverter.ToUInt32(hash, i * 4);   // little-endian on x64 and ARM64
        }

        return "S-1-5-80-" + string.Join('-', parts.Select(p => p.ToString(System.Globalization.CultureInfo.InvariantCulture)));
    }

    /// <summary>The security descriptor WFP's ALE_USER_ID condition matches: grant FWP_ACTRL_MATCH_FILTER (CC) to the SID.</summary>
    public static string Sddl(string sid) => $"D:(A;;CC;;;{sid})";
}

/// <summary>One installed Windows service and, while it runs, its process.</summary>
public sealed record WindowsService(string Name, string DisplayName, int ProcessId, bool Running);

/// <summary>Lists services through the Service Control Manager. Needs no administrator rights.</summary>
public static unsafe class WindowsServiceList
{
    public static IReadOnlyList<WindowsService> Read()
    {
        if (!OperatingSystem.IsWindows())
        {
            return [];
        }

        var scm = Advapi32.OpenSCManager(null, null, Advapi32.SC_MANAGER_ENUMERATE_SERVICE);
        if (scm == IntPtr.Zero)
        {
            return [];
        }

        var result = new List<WindowsService>();
        try
        {
            uint resume = 0;
            uint size = 64 * 1024;
            while (true)
            {
                var buffer = (byte*)System.Runtime.InteropServices.NativeMemory.Alloc(size);
                try
                {
                    uint needed = 0, count = 0;
                    var ok = Advapi32.EnumServicesStatusEx(
                        scm, Advapi32.SC_ENUM_PROCESS_INFO, Advapi32.SERVICE_WIN32, Advapi32.SERVICE_STATE_ALL,
                        buffer, size, &needed, &count, &resume, null);
                    var error = ok ? 0u : (uint)System.Runtime.InteropServices.Marshal.GetLastPInvokeError();
                    if (!ok && error != Advapi32.ERROR_MORE_DATA)
                    {
                        break;
                    }

                    var rows = (ENUM_SERVICE_STATUS_PROCESSW*)buffer;
                    for (var i = 0; i < count; i++)
                    {
                        var r = rows[i];
                        var running = r.dwCurrentState == Advapi32.SERVICE_RUNNING;
                        result.Add(new WindowsService(
                            new string(r.lpServiceName),
                            r.lpDisplayName == null ? new string(r.lpServiceName) : new string(r.lpDisplayName),
                            running ? (int)r.dwProcessId : 0,
                            running));
                    }

                    if (ok)
                    {
                        break;
                    }

                    if (count == 0)
                    {
                        size = Math.Max(size * 2, needed + 4096);
                    }
                }
                finally
                {
                    System.Runtime.InteropServices.NativeMemory.Free(buffer);
                }
            }
        }
        finally
        {
            Advapi32.CloseServiceHandle(scm);
        }

        result.Sort((a, b) => StringComparer.OrdinalIgnoreCase.Compare(a.DisplayName, b.DisplayName));
        return result;
    }

    /// <summary>Running services by process ID, e.g. 1234 → ["Dnscache"].</summary>
    public static IReadOnlyDictionary<int, string[]> ByProcess(IEnumerable<WindowsService> services) =>
        services.Where(s => s.Running && s.ProcessId > 0)
            .GroupBy(s => s.ProcessId)
            .ToDictionary(g => g.Key, g => g.Select(s => s.Name).Order(StringComparer.OrdinalIgnoreCase).ToArray());
}

/// <summary>
/// Works out which service inside svchost.exe made a connection, by finding its socket in the
/// live connection table. Best effort: short-lived sockets may already be closed. Pure logic.
/// </summary>
public static class ServiceAttribution
{
    public static string? Find(
        IReadOnlyList<LiveConnection> table,
        IReadOnlyDictionary<int, string[]> servicesByPid,
        ProtocolType protocol,
        IPEndPoint? local,
        IPEndPoint? remote)
    {
        ArgumentNullException.ThrowIfNull(table);
        ArgumentNullException.ThrowIfNull(servicesByPid);
        if (local is null || local.Port == 0)
        {
            return null;
        }

        LiveConnection? exact = null;
        LiveConnection? fallback = null;
        foreach (var c in table)
        {
            if (c.Protocol != protocol || c.Local.Port != local.Port || !SameOrAny(c.Local.Address, local.Address))
            {
                continue;
            }

            if (protocol == ProtocolType.Tcp && remote is not null && c.Remote is not null)
            {
                if (c.Remote.Equals(remote))
                {
                    exact = c;
                    break;
                }

                continue;   // another connection on the same local port
            }

            fallback ??= c;   // a listener or a UDP socket: same process
        }

        var best = exact ?? fallback;
        if (best is null || !servicesByPid.TryGetValue(best.ProcessId, out var names) || names.Length == 0)
        {
            return null;
        }

        return string.Join(", ", names);
    }

    private static bool SameOrAny(IPAddress bound, IPAddress actual)
    {
        if (bound.Equals(IPAddress.Any) || bound.Equals(IPAddress.IPv6Any))
        {
            return true;
        }

        var a = bound.IsIPv4MappedToIPv6 ? bound.MapToIPv4() : bound;
        var b = actual.IsIPv4MappedToIPv6 ? actual.MapToIPv4() : actual;
        return a.Equals(b);
    }
}

/// <summary>
/// Which of CrioFire's automatic permits (added in Ask and Allow-list modes) are switched on.
/// Stored in <c>%ProgramData%\criofire\auto-rules.txt</c> as lines like <c>svchost=off</c>.
/// </summary>
public sealed class AutoRulePolicy
{
    /// <summary>Services hosted in svchost.exe (DNS, DHCP, Windows Update...).</summary>
    public const string WindowsServices = "svchost";

    /// <summary>The Windows kernel ("System": file sharing, NetBIOS...).</summary>
    public const string WindowsKernel = "system";

    public static IReadOnlyList<string> Names { get; } = [WindowsServices, WindowsKernel];

    private readonly HashSet<string> _disabled = new(StringComparer.OrdinalIgnoreCase);

    public static string DefaultPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "criofire", "auto-rules.txt");

    public static bool IsKnown(string? name) => name is not null && Names.Contains(name, StringComparer.OrdinalIgnoreCase);

    public bool IsEnabled(string name) => !_disabled.Contains(name);

    public void Set(string name, bool enabled)
    {
        if (!IsKnown(name))
        {
            throw new ArgumentException($"Unknown automatic rule '{name}'. Known: {string.Join(", ", Names)}.");
        }

        if (enabled)
        {
            _disabled.Remove(name);
        }
        else
        {
            _disabled.Add(name.ToLowerInvariant());
        }
    }

    public static AutoRulePolicy Parse(string text)
    {
        var policy = new AutoRulePolicy();
        foreach (var raw in (text ?? string.Empty).Split('\n'))
        {
            var line = raw.Trim();
            var eq = line.IndexOf('=', StringComparison.Ordinal);
            if (line.StartsWith('#') || eq <= 0)
            {
                continue;
            }

            var name = line[..eq].Trim();
            if (IsKnown(name) && line[(eq + 1)..].Trim().Equals("off", StringComparison.OrdinalIgnoreCase))
            {
                policy._disabled.Add(name.ToLowerInvariant());
            }
        }

        return policy;
    }

    public string Format()
    {
        var sb = new StringBuilder("# CrioFire automatic rules (Ask and Allow-list modes)\n");
        foreach (var name in Names)
        {
            sb.Append(name).Append('=').Append(IsEnabled(name) ? "on" : "off").Append('\n');
        }

        return sb.ToString();
    }

    public static AutoRulePolicy Load(string path)
    {
        try
        {
            return File.Exists(path) ? Parse(File.ReadAllText(path)) : new AutoRulePolicy();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return new AutoRulePolicy();   // unreadable: keep Windows working
        }
    }

    public void Save(string path)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
        var temp = path + ".tmp";
        File.WriteAllText(temp, Format());
        File.Move(temp, path, overwrite: true);
    }
}
