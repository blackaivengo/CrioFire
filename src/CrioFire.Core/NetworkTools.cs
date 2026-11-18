using System.Net;
using System.Text;

namespace CrioFire.Core;

/// <summary>A Windows program to run with its arguments.</summary>
public sealed record ToolCommand(string Program, string Arguments);

/// <summary>
/// The network checks the app offers for the address of a connection (ping, trace route, name
/// lookup, the connections to it, a port test) and the terminals it opens to it (SSH, Remote
/// Desktop, Telnet, PowerShell), plus the web pages for looking up a program. Only IP addresses
/// are accepted, so nothing from the network can end up as a command-line argument of its own.
/// </summary>
public static class NetworkTools
{
    /// <summary>The address in the form the Windows tools take, or null when it is not an IP address.</summary>
    public static string? Address(string? text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return null;
        }

        var trimmed = text.Trim();
        if (trimmed.StartsWith('[') && trimmed.EndsWith(']'))
        {
            trimmed = trimmed[1..^1];
        }

        return IPAddress.TryParse(trimmed, out var address) && !trimmed.Contains('%', StringComparison.Ordinal)
            ? address.ToString()
            : null;
    }

    /// <summary>Four echo requests.</summary>
    public static ToolCommand Ping(string address) => new("ping.exe", $"-n 4 {Checked(address)}");

    /// <summary>Every router on the way, with names, at most 30 hops, waiting a second per hop.</summary>
    public static ToolCommand TraceRoute(string address) => new("tracert.exe", $"-h 30 -w 1000 {Checked(address)}");

    /// <summary>The address's name in DNS, through the PC's DNS server.</summary>
    public static ToolCommand NameLookup(string address) => new("nslookup.exe", Checked(address));

    /// <summary>All connections and listening ports with their process IDs; <see cref="ConnectionsWith"/> keeps the ones with the address.</summary>
    public static ToolCommand Connections() => new("netstat.exe", "-ano");

    /// <summary>An SSH session, on the connection's port when it is the SSH port or another one given.</summary>
    public static ToolCommand Ssh(string address, int port = 22) =>
        new("ssh.exe", port is > 0 and not 22 ? $"-p {port} {Checked(address)}" : Checked(address));

    /// <summary>Remote Desktop, on another port than 3389 when given.</summary>
    public static ToolCommand RemoteDesktop(string address, int port = 3389)
    {
        var host = Checked(address);
        var target = host.Contains(':', StringComparison.Ordinal) ? $"[{host}]" : host;
        return new("mstsc.exe", port is > 0 and not 3389 ? $"/v:{target}:{port}" : $"/v:{target}");
    }

    /// <summary>A raw TCP session to the port (Telnet client, when Windows has it installed).</summary>
    public static ToolCommand Telnet(string address, int port) => new("telnet.exe", $"{Checked(address)} {Port(port)}");

    /// <summary>PowerShell's connection test: route, name, and whether the port answers.</summary>
    public static ToolCommand PowerShellTest(string address, int port) =>
        new("powershell.exe", $"-NoExit -NoProfile -Command Test-NetConnection -ComputerName {Checked(address)} -Port {Port(port)} -InformationLevel Detailed");

    /// <summary>
    /// The lines of <c>netstat -ano</c> about the address (its header lines too), with the
    /// process name after each line's process ID when <paramref name="processName"/> knows it.
    /// </summary>
    public static IReadOnlyList<string> ConnectionsWith(IEnumerable<string> netstatLines, string address, Func<int, string?>? processName = null)
    {
        ArgumentNullException.ThrowIfNull(netstatLines);
        var wanted = Checked(address);
        var found = new List<string>();
        string? header = null;
        foreach (var line in netstatLines)
        {
            var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length >= 4 && parts[0] is "TCP" or "UDP")
            {
                // TCP: protocol, local, remote, state, pid. UDP: protocol, local, remote (*:*), pid.
                if (Host(parts[1]) == wanted || Host(parts[2]) == wanted)
                {
                    var pid = int.TryParse(parts[^1], out var p) ? p : -1;
                    var name = pid > 0 ? processName?.Invoke(pid) : null;
                    found.Add(name is null ? line.TrimEnd() : $"{line.TrimEnd()}  {name}");
                }
            }
            else if (parts.Length >= 4 && found.Count == 0 && header is null && parts[0].Length > 0 && !char.IsDigit(parts[0][0]))
            {
                header = line.TrimEnd();   // the column titles (in the Windows display language)
            }
        }

        return found.Count == 0 || header is null ? found : [header, .. found];
    }

    /// <summary>Searches the web for a program by its file name and what its file says about it.</summary>
    public static string SearchUrl(string fileName, string? description = null, string? company = null)
    {
        var query = new StringBuilder().Append('"').Append(fileName).Append('"');
        foreach (var extra in new[] { description, company })
        {
            if (!string.IsNullOrWhiteSpace(extra) && !extra.Equals(fileName, StringComparison.OrdinalIgnoreCase))
            {
                query.Append(' ').Append(extra.Trim());
            }
        }

        return "https://www.google.com/search?q=" + Uri.EscapeDataString(query.ToString());
    }

    /// <summary>VirusTotal's report on a file, found by its SHA-256 (nothing is uploaded).</summary>
    public static string VirusTotalUrl(string sha256) =>
        "https://www.virustotal.com/gui/file/" + Uri.EscapeDataString(sha256.ToLowerInvariant());

    /// <summary>Who an internet address belongs to.</summary>
    public static string OwnerUrl(string address) => "https://ipinfo.io/" + Checked(address);

    private static string? Host(string endpoint)
    {
        if (endpoint.StartsWith('['))
        {
            var end = endpoint.IndexOf(']', StringComparison.Ordinal);
            return end > 1 ? Address(endpoint[1..end].Split('%')[0]) : null;
        }

        var colon = endpoint.LastIndexOf(':');
        return Address(colon > 0 ? endpoint[..colon] : endpoint);
    }

    private static string Checked(string address) =>
        Address(address) ?? throw new ArgumentException($"'{address}' is not an IP address.", nameof(address));

    private static int Port(int port) =>
        port is > 0 and <= 65535 ? port : throw new ArgumentOutOfRangeException(nameof(port), port, "A port is 1 to 65535.");
}
