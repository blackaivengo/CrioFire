using System.Runtime.InteropServices;
using CrioFire.Core.Interop;

namespace CrioFire.Core;

/// <summary>Which events a probe subscription asks Windows for.</summary>
public enum NetEventProbeTemplate
{
    /// <summary>No template: every event (what the service uses).</summary>
    None,

    /// <summary>A template with a time range only.</summary>
    AnyTime,

    /// <summary>A template that names the "allowed" event type.</summary>
    AllowedOnly,
}

/// <summary>
/// For tests and diagnosis only: finds out which of Windows' ways of delivering connection
/// events really delivers them on this PC. Subscribes with one version of the call and counts
/// what arrives, by event type (3 = blocked, 6 = allowed). Changes no rule.
/// </summary>
public sealed unsafe class NetEventProbe : IDisposable
{
    /// <summary>FWPM_NET_EVENT_KEYWORD_*: inbound multicast, inbound broadcast, capability drop, capability allow, classify allow.</summary>
    public const uint AllowedKeyword = FwpmNetEventKeywords.CLASSIFY_ALLOW;
    public const uint EveryKeyword = 0x1 | 0x2 | 0x4 | 0x8 | FwpmNetEventKeywords.CLASSIFY_ALLOW;

    /// <summary>FWPM_CONDITION_NET_EVENT_TYPE.</summary>
    private static readonly Guid NetEventTypeCondition = new("206e9996-490e-40cf-b831-b38641eb6fcb");

    private readonly Lock _gate = new();
    private readonly Dictionary<uint, int> _counts = [];
    private readonly int _typeOffset;
    private IntPtr _engine;
    private IntPtr _events;
    private GCHandle _self;

    private NetEventProbe(int typeOffset) => _typeOffset = typeOffset;

    /// <summary>0, or the error Windows gave when subscribing.</summary>
    public uint Error { get; private set; }

    /// <summary>
    /// Subscribes with FwpmNetEventSubscribe<paramref name="version"/> (1, 2 or 4) in a session of
    /// its own. Never throws for a refusal: see <see cref="Error"/>.
    /// </summary>
    public static NetEventProbe Start(int version, NetEventProbeTemplate template)
    {
        // The event's type follows its header: FWPM_NET_EVENT_HEADER2 for version 1, and
        // HEADER3 (an enterprise id, policy flags and an effective name more: 32 bytes) after it.
        var probe = new NetEventProbe(sizeof(FWPM_NET_EVENT_HEADER2) + (version == 1 ? 0 : 32));
        try
        {
            var opened = Fwpuclnt.FwpmEngineOpen0(null, FwpmFlags.RPC_C_AUTHN_WINNT, null, null, out var engine);
            if (opened != FwpErrors.ERROR_SUCCESS)
            {
                probe.Error = opened;
                return probe;
            }

            probe._engine = engine;
            probe._self = GCHandle.Alloc(probe);

            var condition = new FWPM_FILTER_CONDITION0
            {
                fieldKey = NetEventTypeCondition,
                matchType = FWP_MATCH_TYPE.FWP_MATCH_EQUAL,
                conditionValue = new FWP_VALUE0 { type = FWP_DATA_TYPE.FWP_UINT32, value = new FWP_VALUE_UNION { uint32 = FwpmNetEventTypes.FWPM_NET_EVENT_TYPE_CLASSIFY_ALLOW } },
            };
            var enumTemplate = new FWPM_NET_EVENT_ENUM_TEMPLATE0
            {
                startTime = FILETIME.FromDateTime(new DateTime(2000, 1, 1, 0, 0, 0, DateTimeKind.Utc)),
                endTime = FILETIME.FromDateTime(DateTime.UtcNow.AddYears(10)),
                numFilterConditions = template == NetEventProbeTemplate.AllowedOnly ? 1u : 0u,
                filterCondition = template == NetEventProbeTemplate.AllowedOnly ? &condition : null,
            };
            var subscription = new FWPM_NET_EVENT_SUBSCRIPTION0 { enumTemplate = template == NetEventProbeTemplate.None ? null : &enumTemplate };
            var context = (void*)GCHandle.ToIntPtr(probe._self);
            IntPtr events;
            probe.Error = version switch
            {
                1 => Fwpuclnt.FwpmNetEventSubscribe1(engine, &subscription, (delegate* unmanaged<void*, FWPM_NET_EVENT2*, void>)(delegate* unmanaged<void*, void*, void>)&OnEvent, context, &events),
                2 => Fwpuclnt.FwpmNetEventSubscribe2(engine, &subscription, &OnEvent, context, &events),
                4 => Fwpuclnt.FwpmNetEventSubscribe4(engine, &subscription, &OnEvent, context, &events),
                _ => throw new ArgumentOutOfRangeException(nameof(version)),
            };
            if (probe.Error == FwpErrors.ERROR_SUCCESS)
            {
                probe._events = events;
            }
        }
        catch (EntryPointNotFoundException)
        {
            probe.Error = 0x7F;   // ERROR_PROC_NOT_FOUND: this Windows has no such version of the call
        }

        return probe;
    }

    /// <summary>How many events arrived so far, by type.</summary>
    public IReadOnlyDictionary<uint, int> Counts()
    {
        lock (_gate)
        {
            return new Dictionary<uint, int>(_counts);
        }
    }

    public void Dispose()
    {
        if (_events != IntPtr.Zero)
        {
            _ = Fwpuclnt.FwpmNetEventUnsubscribe0(_engine, _events);
            _events = IntPtr.Zero;
        }

        if (_self.IsAllocated)
        {
            _self.Free();
        }

        if (_engine != IntPtr.Zero)
        {
            _ = Fwpuclnt.FwpmEngineClose0(_engine);
            _engine = IntPtr.Zero;
        }
    }

    /// <summary>The machine-wide event keywords now, or null when Windows will not say.</summary>
    public static uint? Keywords()
    {
        if (Fwpuclnt.FwpmEngineOpen0(null, FwpmFlags.RPC_C_AUTHN_WINNT, null, null, out var engine) != FwpErrors.ERROR_SUCCESS)
        {
            return null;
        }

        try
        {
            FWP_VALUE0* current = null;
            if (Fwpuclnt.FwpmEngineGetOption0(engine, FWPM_ENGINE_OPTION.FWPM_ENGINE_NET_EVENT_MATCH_ANY_KEYWORDS, &current) != FwpErrors.ERROR_SUCCESS || current == null)
            {
                return null;
            }

            var keywords = current->type == FWP_DATA_TYPE.FWP_UINT32 ? current->value.uint32 : 0;
            Fwpuclnt.FwpmFreeMemory0((void**)&current);
            return keywords;
        }
        finally
        {
            _ = Fwpuclnt.FwpmEngineClose0(engine);
        }
    }

    /// <summary>Sets the machine-wide event keywords, and whether connections are monitored (FWPM_ENGINE_MONITOR_IPSEC_CONNECTIONS). Returns Windows' two answers.</summary>
    public static (uint Keywords, uint Monitor) SetOptions(uint keywords, bool monitorConnections)
    {
        var opened = Fwpuclnt.FwpmEngineOpen0(null, FwpmFlags.RPC_C_AUTHN_WINNT, null, null, out var engine);
        if (opened != FwpErrors.ERROR_SUCCESS)
        {
            return (opened, opened);
        }

        try
        {
            var value = new FWP_VALUE0 { type = FWP_DATA_TYPE.FWP_UINT32, value = new FWP_VALUE_UNION { uint32 = keywords } };
            var first = Fwpuclnt.FwpmEngineSetOption0(engine, FWPM_ENGINE_OPTION.FWPM_ENGINE_NET_EVENT_MATCH_ANY_KEYWORDS, &value);
            value.value.uint32 = monitorConnections ? 1u : 0u;
            var second = Fwpuclnt.FwpmEngineSetOption0(engine, FWPM_ENGINE_OPTION.FWPM_ENGINE_MONITOR_IPSEC_CONNECTIONS, &value);
            return (first, second);
        }
        finally
        {
            _ = Fwpuclnt.FwpmEngineClose0(engine);
        }
    }

    /// <summary>
    /// Counts the events Windows has stored since <paramref name="fromUtc"/>, by type, asking the
    /// old way. With <paramref name="onlyType"/>, asks Windows for that type alone. (Leaks, as
    /// every such call does: for tests.)
    /// </summary>
    public static (uint Error, IReadOnlyDictionary<uint, int> Counts) Stored(DateTime fromUtc, uint? onlyType = null)
    {
        var counts = new Dictionary<uint, int>();
        var opened = Fwpuclnt.FwpmEngineOpen0(null, FwpmFlags.RPC_C_AUTHN_WINNT, null, null, out var engine);
        if (opened != FwpErrors.ERROR_SUCCESS)
        {
            return (opened, counts);
        }

        try
        {
            var condition = new FWPM_FILTER_CONDITION0
            {
                fieldKey = NetEventTypeCondition,
                matchType = FWP_MATCH_TYPE.FWP_MATCH_EQUAL,
                conditionValue = new FWP_VALUE0 { type = FWP_DATA_TYPE.FWP_UINT32, value = new FWP_VALUE_UNION { uint32 = onlyType ?? 0 } },
            };
            var template = new FWPM_NET_EVENT_ENUM_TEMPLATE0
            {
                startTime = FILETIME.FromDateTime(fromUtc.ToUniversalTime()),
                endTime = FILETIME.FromDateTime(DateTime.UtcNow.AddMinutes(1)),
                numFilterConditions = onlyType is null ? 0u : 1u,
                filterCondition = onlyType is null ? null : &condition,
            };
            IntPtr enumHandle;
            var result = Fwpuclnt.FwpmNetEventCreateEnumHandle0(engine, &template, &enumHandle);
            if (result != FwpErrors.ERROR_SUCCESS)
            {
                return (result, counts);
            }

            try
            {
                while (true)
                {
                    FWPM_NET_EVENT2** entries = null;
                    uint count = 0;
                    result = Fwpuclnt.FwpmNetEventEnum2(engine, enumHandle, 512, &entries, &count);
                    if (result != FwpErrors.ERROR_SUCCESS)
                    {
                        return (result, counts);
                    }

                    for (var i = 0; i < count; i++)
                    {
                        counts[entries[i]->type] = counts.GetValueOrDefault(entries[i]->type) + 1;
                    }

                    if (entries != null)
                    {
                        Fwpuclnt.FwpmFreeMemory0((void**)&entries);
                    }

                    if (count < 512)
                    {
                        return (0, counts);
                    }
                }
            }
            finally
            {
                _ = Fwpuclnt.FwpmNetEventDestroyEnumHandle0(engine, enumHandle);
            }
        }
        finally
        {
            _ = Fwpuclnt.FwpmEngineClose0(engine);
        }
    }

    [UnmanagedCallersOnly]
    private static void OnEvent(void* context, void* e)
    {
        try
        {
            if (context == null || e == null || GCHandle.FromIntPtr((IntPtr)context).Target is not NetEventProbe self)
            {
                return;
            }

            var type = *(uint*)((byte*)e + self._typeOffset);
            lock (self._gate)
            {
                self._counts[type] = self._counts.GetValueOrDefault(type) + 1;
            }
        }
#pragma warning disable CA1031 // Nothing may cross back into Windows' own thread.
        catch (Exception)
        {
        }
#pragma warning restore CA1031
    }
}
