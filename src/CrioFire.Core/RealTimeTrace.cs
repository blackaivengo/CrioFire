using System.Runtime.InteropServices;

namespace CrioFire.Core;

/// <summary>Receives one event's id and data (valid only during the call), on the tracing thread.</summary>
internal delegate void TraceEventHandler(ushort id, ReadOnlySpan<byte> data);

/// <summary>
/// A real-time event tracing session on one provider: nothing is written to disk, each event goes
/// to the handler and is gone. Needs administrator or SYSTEM rights. Used for name lookups
/// (<see cref="DnsClientEvents"/>) and data used per program (<see cref="NetworkUsageEvents"/>).
/// </summary>
/// <param name="bufferKb">Size of each trace buffer in KB (0: Windows' default). Busy providers need more room.</param>
/// <param name="maxBuffers">Most buffers Windows may use (0: its default).</param>
internal sealed unsafe partial class RealTimeTrace(string sessionName, string threadName, Guid provider, TraceEventHandler handler, uint bufferKb = 0, uint maxBuffers = 0)
    : IDisposable
{
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
            var status = StartTraceW(&session, sessionName, properties);
            if (status == ErrorAlreadyExists)
            {
                StopSession();
                status = StartTraceW(&session, sessionName, properties);
            }

            Check(status, "StartTrace");
            _session = session;
        }
        finally
        {
            NativeMemory.Free(properties);
        }

        var id = provider;
        Check(EnableTraceEx2(_session, &id, EventControlCodeEnableProvider, TraceLevelVerbose, ulong.MaxValue, 0, 0, null), "EnableTraceEx2");

        _self = GCHandle.Alloc(this);
        var logFile = (byte*)NativeMemory.AllocZeroed(LogFileSize);
        var name = Marshal.StringToHGlobalUni(sessionName);
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
        { IsBackground = true, Name = threadName };
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

    [UnmanagedCallersOnly]
    private static void OnEvent(EventRecord* record)
    {
        try
        {
            if (record->UserContext != IntPtr.Zero
                && GCHandle.FromIntPtr(record->UserContext).Target is RealTimeTrace self
                && record->ProviderId == self.Provider)
            {
                self.Handler(record->Id, new ReadOnlySpan<byte>((void*)record->UserData, record->UserDataLength));
            }
        }
#pragma warning disable CA1031 // Nothing may cross into the tracing thread's native code: it would end the service.
        catch (Exception)
        {
        }
#pragma warning restore CA1031
    }

    private Guid Provider => provider;

    private TraceEventHandler Handler => handler;

    private byte* NewProperties()
    {
        var p = (byte*)NativeMemory.AllocZeroed(PropertiesBufferSize);
        *(uint*)(p + 0) = PropertiesBufferSize;        // Wnode.BufferSize
        *(uint*)(p + 40) = 1;                          // Wnode.ClientContext: QPC time stamps
        *(uint*)(p + 44) = WnodeFlagTracedGuid;        // Wnode.Flags
        *(uint*)(p + 48) = bufferKb;                   // BufferSize (KB)
        *(uint*)(p + 56) = maxBuffers;                 // MaximumBuffers
        *(uint*)(p + 64) = EventTraceRealTimeMode;     // LogFileMode
        *(uint*)(p + 68) = 1;                          // FlushTimer: deliver within a second
        *(uint*)(p + 116) = PropertiesSize;            // LoggerNameOffset
        return p;
    }

    private void StopSession()
    {
        var properties = NewProperties();
        try
        {
            _ = ControlTraceW(0, sessionName, properties, EventTraceControlStop);
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
