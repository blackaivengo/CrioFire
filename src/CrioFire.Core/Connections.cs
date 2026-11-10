using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace CrioFire.Core;

/// <summary>One open TCP connection or listening/bound socket, with the program that owns it.</summary>
public sealed record LiveConnection(
    ProtocolType Protocol,
    IPEndPoint Local,
    IPEndPoint? Remote,
    string State,
    int ProcessId,
    string? ProcessPath)
{
    public string ProtocolName => Protocol == ProtocolType.Udp ? "UDP" : "TCP";
}

/// <summary>
/// Reads the system's TCP and UDP tables (IP Helper: GetExtendedTcpTable / GetExtendedUdpTable).
/// Needs no administrator rights; programs of other users may show without a path.
/// </summary>
public static unsafe partial class ConnectionTable
{
    private const int AF_INET = 2;
    private const int AF_INET6 = 23;
    private const int TCP_TABLE_OWNER_PID_ALL = 5;
    private const int UDP_TABLE_OWNER_PID = 1;
    private const uint ERROR_INSUFFICIENT_BUFFER = 122;

    public static IReadOnlyList<LiveConnection> Read()
    {
        var result = new List<LiveConnection>();
        var paths = new Dictionary<int, string?>();

        ReadTable(AF_INET, tcp: true, row => AddTcp4(result, (MIB_TCPROW_OWNER_PID*)row, paths));
        ReadTable(AF_INET6, tcp: true, row => AddTcp6(result, (MIB_TCP6ROW_OWNER_PID*)row, paths));
        ReadTable(AF_INET, tcp: false, row => AddUdp4(result, (MIB_UDPROW_OWNER_PID*)row, paths));
        ReadTable(AF_INET6, tcp: false, row => AddUdp6(result, (MIB_UDP6ROW_OWNER_PID*)row, paths));
        return result;
    }

    /// <summary>IP Helper ports are in network byte order in the low 16 bits of a DWORD.</summary>
    public static int PortFromNetworkOrder(uint value) => (int)(((value & 0xFF) << 8) | ((value >> 8) & 0xFF));

    /// <summary>IPv4 addresses are stored in network byte order, i.e. their bytes in memory are the octets.</summary>
    public static IPAddress AddressFromNetworkOrder(uint value) =>
        new([(byte)value, (byte)(value >> 8), (byte)(value >> 16), (byte)(value >> 24)]);

    public static string TcpStateName(uint state) => state switch
    {
        1 => "Closed",
        2 => "Listening",
        3 => "SynSent",
        4 => "SynReceived",
        5 => "Established",
        6 => "FinWait1",
        7 => "FinWait2",
        8 => "CloseWait",
        9 => "Closing",
        10 => "LastAck",
        11 => "TimeWait",
        12 => "DeleteTcb",
        _ => $"State{state}",
    };

    private delegate void RowHandler(byte* row);

    private static void ReadTable(int family, bool tcp, RowHandler handle)
    {
        uint size = 0;
        var result = tcp
            ? GetExtendedTcpTable(null, ref size, false, family, TCP_TABLE_OWNER_PID_ALL, 0)
            : GetExtendedUdpTable(null, ref size, false, family, UDP_TABLE_OWNER_PID, 0);

        for (var attempt = 0; attempt < 5 && result == ERROR_INSUFFICIENT_BUFFER; attempt++)
        {
            size += 4096;   // the table can grow between the two calls
            var buffer = (byte*)NativeMemory.Alloc(size);
            try
            {
                result = tcp
                    ? GetExtendedTcpTable(buffer, ref size, false, family, TCP_TABLE_OWNER_PID_ALL, 0)
                    : GetExtendedUdpTable(buffer, ref size, false, family, UDP_TABLE_OWNER_PID, 0);
                if (result != 0)
                {
                    continue;
                }

                var count = *(uint*)buffer;
                var rowSize = (tcp, family) switch
                {
                    (true, AF_INET) => sizeof(MIB_TCPROW_OWNER_PID),
                    (true, _) => sizeof(MIB_TCP6ROW_OWNER_PID),
                    (false, AF_INET) => sizeof(MIB_UDPROW_OWNER_PID),
                    _ => sizeof(MIB_UDP6ROW_OWNER_PID),
                };

                // Rows start right after the DWORD count (every row type is 4-byte aligned).
                var rows = buffer + sizeof(uint);
                for (var i = 0; i < count; i++)
                {
                    handle(rows + (i * rowSize));
                }

                return;
            }
            finally
            {
                NativeMemory.Free(buffer);
            }
        }
    }

    private static void AddTcp4(List<LiveConnection> list, MIB_TCPROW_OWNER_PID* r, Dictionary<int, string?> paths)
    {
        var listening = r->dwState == 2;
        list.Add(new LiveConnection(
            ProtocolType.Tcp,
            new IPEndPoint(AddressFromNetworkOrder(r->dwLocalAddr), PortFromNetworkOrder(r->dwLocalPort)),
            listening ? null : new IPEndPoint(AddressFromNetworkOrder(r->dwRemoteAddr), PortFromNetworkOrder(r->dwRemotePort)),
            TcpStateName(r->dwState),
            (int)r->dwOwningPid,
            PathOf((int)r->dwOwningPid, paths)));
    }

    private static void AddTcp6(List<LiveConnection> list, MIB_TCP6ROW_OWNER_PID* r, Dictionary<int, string?> paths)
    {
        var listening = r->dwState == 2;
        list.Add(new LiveConnection(
            ProtocolType.Tcp,
            new IPEndPoint(new IPAddress(new ReadOnlySpan<byte>(r->ucLocalAddr, 16), r->dwLocalScopeId), PortFromNetworkOrder(r->dwLocalPort)),
            listening ? null : new IPEndPoint(new IPAddress(new ReadOnlySpan<byte>(r->ucRemoteAddr, 16), r->dwRemoteScopeId), PortFromNetworkOrder(r->dwRemotePort)),
            TcpStateName(r->dwState),
            (int)r->dwOwningPid,
            PathOf((int)r->dwOwningPid, paths)));
    }

    private static void AddUdp4(List<LiveConnection> list, MIB_UDPROW_OWNER_PID* r, Dictionary<int, string?> paths) =>
        list.Add(new LiveConnection(
            ProtocolType.Udp,
            new IPEndPoint(AddressFromNetworkOrder(r->dwLocalAddr), PortFromNetworkOrder(r->dwLocalPort)),
            null,
            "Bound",
            (int)r->dwOwningPid,
            PathOf((int)r->dwOwningPid, paths)));

    private static void AddUdp6(List<LiveConnection> list, MIB_UDP6ROW_OWNER_PID* r, Dictionary<int, string?> paths) =>
        list.Add(new LiveConnection(
            ProtocolType.Udp,
            new IPEndPoint(new IPAddress(new ReadOnlySpan<byte>(r->ucLocalAddr, 16), r->dwLocalScopeId), PortFromNetworkOrder(r->dwLocalPort)),
            null,
            "Bound",
            (int)r->dwOwningPid,
            PathOf((int)r->dwOwningPid, paths)));

    private static string? PathOf(int pid, Dictionary<int, string?> cache)
    {
        if (cache.TryGetValue(pid, out var cached))
        {
            return cached;
        }

        string? path = pid switch
        {
            0 => "System Idle",
            4 => "System",
            _ => null,
        };

        if (path is null)
        {
            try
            {
                using var process = Process.GetProcessById(pid);
                try
                {
                    path = process.MainModule?.FileName;
                }
                catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException or NotSupportedException)
                {
                    path = process.ProcessName;   // another user's or a protected process: name only
                }
            }
            catch (Exception ex) when (ex is ArgumentException or InvalidOperationException)
            {
                path = null;   // already exited
            }
        }

        cache[pid] = path;
        return path;
    }

    [LibraryImport("iphlpapi.dll")]
    private static partial uint GetExtendedTcpTable(void* table, ref uint size, [MarshalAs(UnmanagedType.Bool)] bool order, int family, int tableClass, uint reserved);

    [LibraryImport("iphlpapi.dll")]
    private static partial uint GetExtendedUdpTable(void* table, ref uint size, [MarshalAs(UnmanagedType.Bool)] bool order, int family, int tableClass, uint reserved);
}

// iprtrmib.h / tcpmib.h / udpmib.h row layouts.
[StructLayout(LayoutKind.Sequential)]
internal struct MIB_TCPROW_OWNER_PID
{
    public uint dwState;
    public uint dwLocalAddr;
    public uint dwLocalPort;
    public uint dwRemoteAddr;
    public uint dwRemotePort;
    public uint dwOwningPid;
}

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct MIB_TCP6ROW_OWNER_PID
{
    public fixed byte ucLocalAddr[16];
    public uint dwLocalScopeId;
    public uint dwLocalPort;
    public fixed byte ucRemoteAddr[16];
    public uint dwRemoteScopeId;
    public uint dwRemotePort;
    public uint dwState;
    public uint dwOwningPid;
}

[StructLayout(LayoutKind.Sequential)]
internal struct MIB_UDPROW_OWNER_PID
{
    public uint dwLocalAddr;
    public uint dwLocalPort;
    public uint dwOwningPid;
}

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct MIB_UDP6ROW_OWNER_PID
{
    public fixed byte ucLocalAddr[16];
    public uint dwLocalScopeId;
    public uint dwLocalPort;
    public uint dwOwningPid;
}
