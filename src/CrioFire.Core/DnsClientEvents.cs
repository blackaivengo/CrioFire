using System.Net;
using System.Runtime.InteropServices;

namespace CrioFire.Core;

/// <summary>
/// Follows Windows' own name lookups as they complete, through a real-time event tracing session on
/// the Microsoft-Windows-DNS-Client provider (event 3008, "DNS query is completed"). Nothing is
/// written to disk: each lookup goes to <see cref="Lookup"/> and is gone. Needs administrator or
/// SYSTEM rights. Lookups an application makes itself (a browser's own encrypted DNS) are not seen.
/// </summary>
public sealed unsafe partial class DnsClientEvents : IDisposable
{
    public const string SessionName = "CrioFire-DNS";

    private static readonly Guid DnsClientProvider = new("1c95126e-7eea-49a9-a3fe-a378b03ddb4d");
    private const ushort QueryCompleted = 3008;

    private const uint WnodeFlagTracedGuid = 0x00020000;
    private const uint EventTraceRealTimeMode = 0x00000100;
    private const uint ProcessTraceModeRealTime = 0x00000100;
    private const uint ProcessTraceModeEventRecord = 0x10000000;
    private const uint EventTraceControlStop = 1;
    private const uint EventControlCodeEnableProvider = 1;
    private const byte TraceLevelVerbose = 5;
    private const int ErrorAlreadyExists = 183;
    private const ulong InvalidTraceHandle = ulong.MaxValue;

    // EVENT_TRACE_PROPERTIES on 64-bit Windows: 120 bytes, followed here by the session name.
    private const int PropertiesSize = 120;
    private const int PropertiesBufferSize = PropertiesSize + 1024;

    // EVENT_TRACE_LOGFILEW on 64-bit Windows: 448 bytes.
    private const int LogFileSize = 448;

    private ulong _session;
    private ulong _trace = InvalidTraceHandle;
    private GCHandle _self;
    private Thread? _thread;

    /// <summary>Raised on the tracing thread for each completed lookup that returned addresses.</summary>
    public event Action<DnsLookup>? Lookup;

    /// <summary>Starts the session and its reading thread. Throws <see cref="IOException"/> if Windows refuses.</summary>
    public void Start()
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("Event tracing needs Windows.");
        }

        StopSession();   // a session left by a service that did not stop cleanly
        var properties = NewProperties();
        try
        {
            ulong session;
            var status = StartTraceW(&session, SessionName, properties);
            if (status == ErrorAlreadyExists)
            {
                StopSession();
                status = StartTraceW(&session, SessionName, properties);
            }

            Check(status, "StartTrace");
            _session = session;
        }
        finally
        {
            NativeMemory.Free(properties);
        }

        var provider = DnsClientProvider;
        Check(EnableTraceEx2(_session, &provider, EventControlCodeEnableProvider, TraceLevelVerbose, ulong.MaxValue, 0, 0, null), "EnableTraceEx2");

        _self = GCHandle.Alloc(this);
        var logFile = (byte*)NativeMemory.AllocZeroed(LogFileSize);
        var name = Marshal.StringToHGlobalUni(SessionName);
        try
        {
            *(IntPtr*)(logFile + 8) = name;                                                     // LoggerName
            *(uint*)(logFile + 28) = ProcessTraceModeRealTime | ProcessTraceModeEventRecord;    // ProcessTraceMode
            *(IntPtr*)(logFile + 424) = (IntPtr)(delegate* unmanaged<EventRecord*, void>)&OnEvent;   // EventRecordCallback
            *(IntPtr*)(logFile + 440) = GCHandle.ToIntPtr(_self);                               // Context
            _trace = OpenTraceW(logFile);
        }
        finally
        {
            Marshal.FreeHGlobal(name);
            NativeMemory.Free(logFile);
        }

        if (_trace == InvalidTraceHandle)
        {
            var error = Marshal.GetLastPInvokeError();
            Dispose();
            throw new IOException($"OpenTrace failed ({error}).");
        }

        var trace = _trace;
        _thread = new Thread(() =>
        {
            var handle = trace;
            _ = ProcessTrace(&handle, 1, null, null);   // returns when the session stops
        })
        { IsBackground = true, Name = "CrioFire DNS lookups" };
        _thread.Start();
    }

    public void Dispose()
    {
        if (_session != 0)
        {
            StopSession();   // ProcessTrace returns once the session stops
            _session = 0;
        }

        if (_trace != InvalidTraceHandle)
        {
            _ = CloseTrace(_trace);
            _trace = InvalidTraceHandle;
        }

        _thread?.Join(TimeSpan.FromSeconds(5));
        _thread = null;
        if (_self.IsAllocated)
        {
            _self.Free();
        }
    }

    /// <summary>
    /// Parses QueryResults as the DNS client writes it: "type:  5 cdn.example.net;::ffff:93.184.216.34;2606:2800::1;"
    /// (CNAME names after "type:  5", IPv4 addresses often as IPv4-mapped IPv6).
    /// </summary>
    public static (List<string> Aliases, List<IPAddress> Addresses) ParseResults(string? results)
    {
        var aliases = new List<string>();
        var addresses = new List<IPAddress>();
        foreach (var part in (results ?? string.Empty).Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (part.StartsWith("type:", StringComparison.OrdinalIgnoreCase))
            {
                var fields = part[5..].Split(' ', StringSplitOptions.RemoveEmptyEntries);
                if (fields.Length >= 2 && fields[0] == "5")
                {
                    aliases.Add(fields[1].TrimEnd('.').ToLowerInvariant());
                }
            }
            else if (IPAddress.TryParse(part, out var address))
            {
                addresses.Add(address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address);
            }
        }

        return (aliases, addresses);
    }

    /// <summary>
    /// Reads event 3008's data: QueryName (UTF-16, null-terminated), QueryType (UInt32),
    /// QueryOptions (UInt64), QueryStatus (UInt32), QueryResults (UTF-16, null-terminated).
    /// Null for anything that does not fit that shape, or a lookup that failed.
    /// </summary>
    public static DnsLookup? ParseQueryCompleted(ReadOnlySpan<byte> data)
    {
        if (!TryReadString(ref data, out var name) || data.Length < 16)
        {
            return null;
        }

        var status = MemoryMarshal.Read<uint>(data[12..]);
        data = data[16..];
        if (status != 0 || name.Length == 0 || !TryReadString(ref data, out var results))
        {
            return null;
        }

        var (aliases, addresses) = ParseResults(results);
        return addresses.Count == 0 ? null : new DnsLookup(name.TrimEnd('.').ToLowerInvariant(), aliases, addresses);
    }

    private static bool TryReadString(ref ReadOnlySpan<byte> data, out string text)
    {
        var chars = MemoryMarshal.Cast<byte, char>(data[..(data.Length & ~1)]);
        var end = chars.IndexOf('\0');
        if (end < 0)
        {
            text = string.Empty;
            return false;
        }

        text = new string(chars[..end]);
        data = data[((end + 1) * 2)..];
        return true;
    }

    [UnmanagedCallersOnly]
    private static void OnEvent(EventRecord* record)
    {
        try
        {
            if (record->ProviderId != DnsClientProvider || record->Id != QueryCompleted || record->UserContext == IntPtr.Zero)
            {
                return;
            }

            var lookup = ParseQueryCompleted(new ReadOnlySpan<byte>((void*)record->UserData, record->UserDataLength));
            if (lookup is not null && GCHandle.FromIntPtr(record->UserContext).Target is DnsClientEvents self)
            {
                self.Lookup?.Invoke(lookup);
            }
        }
#pragma warning disable CA1031 // Nothing may cross into the tracing thread's native code: it would end the service.
        catch (Exception)
        {
        }
#pragma warning restore CA1031
    }

    private static byte* NewProperties()
    {
        var p = (byte*)NativeMemory.AllocZeroed(PropertiesBufferSize);
        *(uint*)(p + 0) = PropertiesBufferSize;        // Wnode.BufferSize
        *(uint*)(p + 40) = 1;                          // Wnode.ClientContext: QPC time stamps
        *(uint*)(p + 44) = WnodeFlagTracedGuid;        // Wnode.Flags
        *(uint*)(p + 64) = EventTraceRealTimeMode;     // LogFileMode
        *(uint*)(p + 68) = 1;                          // FlushTimer: deliver within a second
        *(uint*)(p + 116) = PropertiesSize;            // LoggerNameOffset
        return p;
    }

    private static void StopSession()
    {
        var properties = NewProperties();
        try
        {
            _ = ControlTraceW(0, SessionName, properties, EventTraceControlStop);
        }
        finally
        {
            NativeMemory.Free(properties);
        }
    }

    private static void Check(int status, string call)
    {
        if (status != 0)
        {
            throw new IOException($"{call} failed ({status}).");
        }
    }

    /// <summary>EVENT_RECORD on 64-bit Windows (the parts read here).</summary>
    [StructLayout(LayoutKind.Explicit, Size = 112)]
    private struct EventRecord
    {
        [FieldOffset(24)] public Guid ProviderId;       // EventHeader.ProviderId
        [FieldOffset(40)] public ushort Id;             // EventHeader.EventDescriptor.Id
        [FieldOffset(86)] public ushort UserDataLength;
        [FieldOffset(96)] public IntPtr UserData;
        [FieldOffset(104)] public IntPtr UserContext;   // the Context given to OpenTrace
    }

    [LibraryImport("advapi32.dll", StringMarshalling = StringMarshalling.Utf16)]
    private static partial int StartTraceW(ulong* sessionHandle, string sessionName, byte* properties);

    [LibraryImport("advapi32.dll", StringMarshalling = StringMarshalling.Utf16)]
    private static partial int ControlTraceW(ulong sessionHandle, string sessionName, byte* properties, uint controlCode);

    [LibraryImport("advapi32.dll")]
    private static partial int EnableTraceEx2(ulong sessionHandle, Guid* providerId, uint controlCode, byte level, ulong matchAnyKeyword, ulong matchAllKeyword, uint timeout, void* enableParameters);

    [LibraryImport("advapi32.dll", SetLastError = true)]
    private static partial ulong OpenTraceW(byte* logFile);

    [LibraryImport("advapi32.dll")]
    private static partial int ProcessTrace(ulong* handleArray, uint handleCount, void* startTime, void* endTime);

    [LibraryImport("advapi32.dll")]
    private static partial int CloseTrace(ulong traceHandle);
}
