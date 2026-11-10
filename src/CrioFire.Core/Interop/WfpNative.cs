using System.Runtime.InteropServices;

namespace CrioFire.Core.Interop;

// Hand-written bindings for the parts of the Windows Filtering Platform management API
// (fwpuclnt.dll, declared in fwpmu.h / fwpmtypes.h / fwptypes.h) that CrioFire uses.
// Layouts follow the Windows SDK for 64-bit processes (x64 and ARM64): pointers are 8 bytes.
// tests/CrioFire.Tests/InteropLayoutTests.cs pins every struct size and key offset.

internal enum FWP_DATA_TYPE : uint
{
    FWP_EMPTY = 0,
    FWP_UINT8 = 1,
    FWP_UINT16 = 2,
    FWP_UINT32 = 3,
    FWP_UINT64 = 4,
    FWP_BYTE_BLOB_TYPE = 12,
}

internal enum FWP_MATCH_TYPE : uint
{
    FWP_MATCH_EQUAL = 0,
    FWP_MATCH_FLAGS_NONE_SET = 8,
}

internal static class FwpConditionFlags
{
    /// <summary>FWP_CONDITION_FLAG_IS_LOOPBACK: the connection stays on this machine.</summary>
    public const uint FWP_CONDITION_FLAG_IS_LOOPBACK = 0x00000001;
}

internal static class FwpActionType
{
    public const uint FWP_ACTION_FLAG_TERMINATING = 0x00001000;
    public const uint FWP_ACTION_BLOCK = 0x00000001 | FWP_ACTION_FLAG_TERMINATING;
    public const uint FWP_ACTION_PERMIT = 0x00000002 | FWP_ACTION_FLAG_TERMINATING;
}

internal static class FwpmFlags
{
    public const uint FWPM_PROVIDER_FLAG_PERSISTENT = 0x00000001;
    public const uint FWPM_SUBLAYER_FLAG_PERSISTENT = 0x00000001;
    public const uint FWPM_FILTER_FLAG_PERSISTENT = 0x00000001;

    /// <summary>RPC_C_AUTHN_WINNT: authenticate to the local BFE with the caller's token.</summary>
    public const uint RPC_C_AUTHN_WINNT = 10;
}

internal static class FwpErrors
{
    public const uint ERROR_SUCCESS = 0;
    public const uint ERROR_ACCESS_DENIED = 5;
    public const uint FWP_E_FILTER_NOT_FOUND = 0x80320003;
    public const uint FWP_E_PROVIDER_NOT_FOUND = 0x80320005;
    public const uint FWP_E_SUBLAYER_NOT_FOUND = 0x80320007;
    public const uint FWP_E_NOT_FOUND = 0x80320008;
    public const uint FWP_E_ALREADY_EXISTS = 0x80320009;
    public const uint FWP_E_IN_USE = 0x8032000A;
}

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct FWP_BYTE_BLOB
{
    public uint size;
    public byte* data;
}

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct FWPM_DISPLAY_DATA0
{
    public char* name;
    public char* description;
}

/// <summary>The union inside FWP_VALUE0 / FWP_CONDITION_VALUE0: one pointer-sized slot.</summary>
[StructLayout(LayoutKind.Explicit, Size = 8)]
internal unsafe struct FWP_VALUE_UNION
{
    [FieldOffset(0)] public byte uint8;
    [FieldOffset(0)] public ushort uint16;
    [FieldOffset(0)] public uint uint32;
    [FieldOffset(0)] public ulong* uint64;
    [FieldOffset(0)] public FWP_BYTE_BLOB* byteBlob;
}

/// <summary>FWP_VALUE0; FWP_CONDITION_VALUE0 has the same layout.</summary>
[StructLayout(LayoutKind.Sequential)]
internal struct FWP_VALUE0
{
    public FWP_DATA_TYPE type;
    public FWP_VALUE_UNION value;
}

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct FWPM_PROVIDER0
{
    public Guid providerKey;
    public FWPM_DISPLAY_DATA0 displayData;
    public uint flags;
    public FWP_BYTE_BLOB providerData;
    public char* serviceName;
}

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct FWPM_SUBLAYER0
{
    public Guid subLayerKey;
    public FWPM_DISPLAY_DATA0 displayData;
    public uint flags;
    public Guid* providerKey;
    public FWP_BYTE_BLOB providerData;
    public ushort weight;
}

[StructLayout(LayoutKind.Sequential)]
internal struct FWPM_FILTER_CONDITION0
{
    public Guid fieldKey;
    public FWP_MATCH_TYPE matchType;
    public FWP_VALUE0 conditionValue;
}

[StructLayout(LayoutKind.Sequential)]
internal struct FWPM_ACTION0
{
    public uint type;

    /// <summary>Union of filterType / calloutKey; unused for plain block and permit.</summary>
    public Guid filterTypeOrCalloutKey;
}

/// <summary>Union of UINT64 rawContext and GUID providerContextKey (8-byte aligned).</summary>
[StructLayout(LayoutKind.Explicit, Size = 16)]
internal struct FWPM_FILTER0_CONTEXT
{
    [FieldOffset(0)] public ulong rawContext;
    [FieldOffset(0)] public Guid providerContextKey;
}

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct FWPM_FILTER0
{
    public Guid filterKey;
    public FWPM_DISPLAY_DATA0 displayData;
    public uint flags;
    public Guid* providerKey;
    public FWP_BYTE_BLOB providerData;
    public Guid layerKey;
    public Guid subLayerKey;
    public FWP_VALUE0 weight;
    public uint numFilterConditions;
    public FWPM_FILTER_CONDITION0* filterCondition;
    public FWPM_ACTION0 action;
    public FWPM_FILTER0_CONTEXT context;
    public Guid* reserved;
    public ulong filterId;
    public FWP_VALUE0 effectiveWeight;
}

// ---- Net events (fwpmtypes.h): what the filtering engine dropped. Version 0 structs, enumerated by polling.

internal enum FWPM_ENGINE_OPTION : uint
{
    FWPM_ENGINE_COLLECT_NET_EVENTS = 0,
}

internal static class FwpmNetEventTypes
{
    public const uint FWPM_NET_EVENT_TYPE_CLASSIFY_DROP = 3;
}

internal static class FwpmNetEventFlags
{
    public const uint IP_PROTOCOL_SET = 0x00000001;
    public const uint LOCAL_ADDR_SET = 0x00000002;
    public const uint REMOTE_ADDR_SET = 0x00000004;
    public const uint LOCAL_PORT_SET = 0x00000008;
    public const uint REMOTE_PORT_SET = 0x00000010;
    public const uint APP_ID_SET = 0x00000020;
    public const uint IP_VERSION_SET = 0x00000100;
}

/// <summary>Win32 FILETIME: 100 ns ticks since 1601-01-01 UTC, as two 32-bit halves.</summary>
[StructLayout(LayoutKind.Sequential)]
internal struct FILETIME
{
    public uint dwLowDateTime;
    public uint dwHighDateTime;

    public static FILETIME FromDateTime(DateTime utc)
    {
        var ticks = utc.ToFileTimeUtc();
        return new FILETIME { dwLowDateTime = unchecked((uint)ticks), dwHighDateTime = (uint)(ticks >> 32) };
    }

    public readonly DateTime ToDateTime() => DateTime.FromFileTimeUtc(((long)dwHighDateTime << 32) | dwLowDateTime);
}

/// <summary>Union of UINT32 (IPv4, host byte order) and FWP_BYTE_ARRAY16 (IPv6, network order).</summary>
[StructLayout(LayoutKind.Explicit, Size = 16)]
internal unsafe struct FWP_ADDR_UNION
{
    [FieldOffset(0)] public uint v4;
    [FieldOffset(0)] public fixed byte v6[16];
}

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct FWPM_NET_EVENT_HEADER0
{
    public FILETIME timeStamp;
    public uint flags;
    public uint ipVersion;          // FWP_IP_VERSION: 0 = V4, 1 = V6
    public byte ipProtocol;
    public FWP_ADDR_UNION localAddr;
    public FWP_ADDR_UNION remoteAddr;
    public ushort localPort;
    public ushort remotePort;
    public uint scopeId;
    public FWP_BYTE_BLOB appId;      // NT path, UTF-16, NUL-terminated
    public void* userId;             // SID*
}

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct FWPM_NET_EVENT0
{
    public FWPM_NET_EVENT_HEADER0 header;
    public uint type;

    /// <summary>Union of pointers to the per-type details; for CLASSIFY_DROP it is FWPM_NET_EVENT_CLASSIFY_DROP0*.</summary>
    public void* details;
}

[StructLayout(LayoutKind.Sequential)]
internal struct FWPM_NET_EVENT_CLASSIFY_DROP0
{
    public ulong filterId;
    public ushort layerId;
}

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct FWPM_NET_EVENT_ENUM_TEMPLATE0
{
    public FILETIME startTime;
    public FILETIME endTime;
    public uint numFilterConditions;
    public FWPM_FILTER_CONDITION0* filterCondition;
}

internal static unsafe partial class Kernel32
{
    [LibraryImport("kernel32.dll", EntryPoint = "QueryDosDeviceW", StringMarshalling = StringMarshalling.Utf16, SetLastError = true)]
    public static partial uint QueryDosDevice(string deviceName, char* targetPath, uint maxChars);
}

internal static unsafe partial class Fwpuclnt
{
    [LibraryImport(Dll)]
    public static partial uint FwpmEngineSetOption0(IntPtr engineHandle, FWPM_ENGINE_OPTION option, FWP_VALUE0* newValue);

    [LibraryImport(Dll)]
    public static partial uint FwpmNetEventCreateEnumHandle0(IntPtr engineHandle, FWPM_NET_EVENT_ENUM_TEMPLATE0* enumTemplate, IntPtr* enumHandle);

    [LibraryImport(Dll)]
    public static partial uint FwpmNetEventEnum0(IntPtr engineHandle, IntPtr enumHandle, uint numEntriesRequested, FWPM_NET_EVENT0*** entries, uint* numEntriesReturned);

    [LibraryImport(Dll)]
    public static partial uint FwpmNetEventDestroyEnumHandle0(IntPtr engineHandle, IntPtr enumHandle);
}

internal static unsafe partial class Fwpuclnt
{
    private const string Dll = "fwpuclnt.dll";

    [LibraryImport(Dll)]
    public static partial uint FwpmEngineOpen0(char* serverName, uint authnService, void* authIdentity, void* session, out IntPtr engineHandle);

    [LibraryImport(Dll)]
    public static partial uint FwpmEngineClose0(IntPtr engineHandle);

    [LibraryImport(Dll)]
    public static partial uint FwpmTransactionBegin0(IntPtr engineHandle, uint flags);

    [LibraryImport(Dll)]
    public static partial uint FwpmTransactionCommit0(IntPtr engineHandle);

    [LibraryImport(Dll)]
    public static partial uint FwpmTransactionAbort0(IntPtr engineHandle);

    [LibraryImport(Dll)]
    public static partial uint FwpmProviderAdd0(IntPtr engineHandle, FWPM_PROVIDER0* provider, void* securityDescriptor);

    [LibraryImport(Dll)]
    public static partial uint FwpmProviderGetByKey0(IntPtr engineHandle, Guid* key, FWPM_PROVIDER0** provider);

    [LibraryImport(Dll)]
    public static partial uint FwpmProviderDeleteByKey0(IntPtr engineHandle, Guid* key);

    [LibraryImport(Dll)]
    public static partial uint FwpmSubLayerAdd0(IntPtr engineHandle, FWPM_SUBLAYER0* subLayer, void* securityDescriptor);

    [LibraryImport(Dll)]
    public static partial uint FwpmSubLayerDeleteByKey0(IntPtr engineHandle, Guid* key);

    [LibraryImport(Dll)]
    public static partial uint FwpmFilterAdd0(IntPtr engineHandle, FWPM_FILTER0* filter, void* securityDescriptor, ulong* id);

    [LibraryImport(Dll)]
    public static partial uint FwpmFilterDeleteById0(IntPtr engineHandle, ulong id);

    [LibraryImport(Dll)]
    public static partial uint FwpmFilterCreateEnumHandle0(IntPtr engineHandle, void* enumTemplate, IntPtr* enumHandle);

    [LibraryImport(Dll)]
    public static partial uint FwpmFilterEnum0(IntPtr engineHandle, IntPtr enumHandle, uint numEntriesRequested, FWPM_FILTER0*** entries, uint* numEntriesReturned);

    [LibraryImport(Dll)]
    public static partial uint FwpmFilterDestroyEnumHandle0(IntPtr engineHandle, IntPtr enumHandle);

    [LibraryImport(Dll)]
    public static partial uint FwpmGetAppIdFromFileName0(char* fileName, FWP_BYTE_BLOB** appId);

    [LibraryImport(Dll)]
    public static partial void FwpmFreeMemory0(void** p);
}
