using System.Runtime.InteropServices;
using System.Net;
using System.Net.Sockets;
using CrioFire.Core.Interop;

namespace CrioFire.Core;

/// <summary>
/// A session with the Windows Base Filtering Engine (BFE), scoped to CrioFire's own
/// provider and sublayer. Every method needs administrator rights.
/// </summary>
/// <remarks>
/// Safety rules for this prototype:
/// <list type="bullet">
/// <item>Rules only ever match one application; there is no "block everything" filter,
/// so a mistake cannot cut the whole PC off the network.</item>
/// <item><see cref="RemoveAllFilters"/> (criofire panic) always removes every CrioFire filter.</item>
/// </list>
/// </remarks>
public sealed unsafe class WfpEngine : IDisposable
{
    private const string ProviderName = "CrioFire Private Firewall";
    private const string ProviderDescription = "criofire-provider: CrioFire Private Firewall by CrioSoft LLC";
    private const string SubLayerName = "CrioFire rules";
    private const string SubLayerDescription = "criofire-sublayer: per-app rules set by CrioFire Private Firewall";

    /// <summary>
    /// CrioFire's sublayer weight. Across sublayers a block always beats a permit, so CrioFire
    /// can add blocks on top of Windows Firewall but a CrioFire permit cannot override its blocks.
    /// </summary>
    private const ushort SubLayerWeight = 0x8000;

    private IntPtr _handle;

    private WfpEngine(IntPtr handle) => _handle = handle;

    /// <summary>Opens a session with the local filtering engine.</summary>
    public static WfpEngine Open()
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("CrioFire needs Windows 10 or 11.");
        }

        if (!Environment.Is64BitProcess)
        {
            throw new PlatformNotSupportedException("CrioFire runs only as a 64-bit process (x64 or ARM64).");
        }

        Check("FwpmEngineOpen0", Fwpuclnt.FwpmEngineOpen0(null, FwpmFlags.RPC_C_AUTHN_WINNT, null, null, out var handle));
        return new WfpEngine(handle);
    }

    /// <summary>True when the criofire-provider is registered with the BFE.</summary>
    public bool IsInstalled()
    {
        ThrowIfDisposed();
        var key = WfpIds.ProviderKey;
        FWPM_PROVIDER0* provider = null;
        var result = Fwpuclnt.FwpmProviderGetByKey0(_handle, &key, &provider);
        if (result == FwpErrors.FWP_E_PROVIDER_NOT_FOUND)
        {
            return false;
        }

        // Expected not-found code per winerror.h; confirm on real hardware during Phase 0 testing.
        Check("FwpmProviderGetByKey0", result);
        Fwpuclnt.FwpmFreeMemory0((void**)&provider);
        return true;
    }

    /// <summary>Registers the criofire-provider and criofire-sublayer. Safe to call repeatedly.</summary>
    public void Install()
    {
        ThrowIfDisposed();
        using var tx = BeginTransaction();
        {
            var providerKey = WfpIds.ProviderKey;
            fixed (char* pName = ProviderName)
            fixed (char* pDesc = ProviderDescription)
            {
                var provider = new FWPM_PROVIDER0
                {
                    providerKey = providerKey,
                    displayData = new FWPM_DISPLAY_DATA0 { name = pName, description = pDesc },
                    flags = FwpmFlags.FWPM_PROVIDER_FLAG_PERSISTENT,
                };
                CheckAllowExisting("FwpmProviderAdd0", Fwpuclnt.FwpmProviderAdd0(_handle, &provider, null));
            }

            fixed (char* pName = SubLayerName)
            fixed (char* pDesc = SubLayerDescription)
            {
                var subLayer = new FWPM_SUBLAYER0
                {
                    subLayerKey = WfpIds.SubLayerKey,
                    displayData = new FWPM_DISPLAY_DATA0 { name = pName, description = pDesc },
                    flags = FwpmFlags.FWPM_SUBLAYER_FLAG_PERSISTENT,
                    providerKey = &providerKey,
                    weight = SubLayerWeight,
                };
                CheckAllowExisting("FwpmSubLayerAdd0", Fwpuclnt.FwpmSubLayerAdd0(_handle, &subLayer, null));
            }
        }

        tx.Commit();
        EnableNetEventCollection();
    }

    /// <summary>
    /// Turns on the engine's net event collection (FWPM_ENGINE_COLLECT_NET_EVENTS), so dropped
    /// connections can be read back with <see cref="ReadBlockedConnections"/>. A machine-wide
    /// setting that Windows usually has on already; CrioFire never turns it off.
    /// </summary>
    public void EnableNetEventCollection()
    {
        ThrowIfDisposed();
        var value = new FWP_VALUE0 { type = FWP_DATA_TYPE.FWP_UINT32, value = new FWP_VALUE_UNION { uint32 = 1 } };
        Check("FwpmEngineSetOption0", Fwpuclnt.FwpmEngineSetOption0(_handle, FWPM_ENGINE_OPTION.FWPM_ENGINE_COLLECT_NET_EVENTS, &value));
    }

    /// <summary>
    /// Reads connection attempts the filtering engine dropped between <paramref name="fromUtc"/> and
    /// <paramref name="toUtc"/> (default: now). The engine keeps a limited in-memory history, so poll
    /// regularly. With <paramref name="crioFireOnly"/>, drops caused by other firewalls are left out.
    /// </summary>
    public IReadOnlyList<BlockedConnection> ReadBlockedConnections(DateTime fromUtc, DateTime? toUtc = null, bool crioFireOnly = true, NtPathMapper? paths = null)
    {
        ThrowIfDisposed();
        paths ??= NtPathMapper.FromSystem();
        var ours = ListFilters().ToDictionary(f => f.FilterId);
        var result = new List<BlockedConnection>();

        var template = new FWPM_NET_EVENT_ENUM_TEMPLATE0
        {
            startTime = FILETIME.FromDateTime(fromUtc.ToUniversalTime()),
            endTime = FILETIME.FromDateTime((toUtc ?? DateTime.UtcNow).ToUniversalTime()),
        };

        IntPtr enumHandle;
        Check("FwpmNetEventCreateEnumHandle0", Fwpuclnt.FwpmNetEventCreateEnumHandle0(_handle, &template, &enumHandle));
        try
        {
            while (true)
            {
                FWPM_NET_EVENT0** entries = null;
                uint count = 0;
                Check("FwpmNetEventEnum0", Fwpuclnt.FwpmNetEventEnum0(_handle, enumHandle, 256, &entries, &count));
                try
                {
                    for (var i = 0; i < count; i++)
                    {
                        var e = entries[i];
                        if (e->type != FwpmNetEventTypes.FWPM_NET_EVENT_TYPE_CLASSIFY_DROP || e->details == null)
                        {
                            continue;
                        }

                        var drop = (FWPM_NET_EVENT_CLASSIFY_DROP0*)e->details;
                        ours.TryGetValue(drop->filterId, out var rule);
                        if (crioFireOnly && rule is null)
                        {
                            continue;
                        }

                        result.Add(Decode(&e->header, drop->filterId, rule, paths));
                    }
                }
                finally
                {
                    if (entries != null)
                    {
                        Fwpuclnt.FwpmFreeMemory0((void**)&entries);
                    }
                }

                if (count < 256)
                {
                    break;
                }
            }
        }
        finally
        {
            _ = Fwpuclnt.FwpmNetEventDestroyEnumHandle0(_handle, enumHandle);
        }

        result.Sort((a, b) => a.TimeUtc.CompareTo(b.TimeUtc));
        return result;
    }

    private static BlockedConnection Decode(FWPM_NET_EVENT_HEADER0* h, ulong filterId, CrioFireFilter? rule, NtPathMapper paths)
    {
        string? app = null;
        if ((h->flags & FwpmNetEventFlags.APP_ID_SET) != 0 && h->appId.data != null)
        {
            var nt = NetEventDecoding.DecodeAppId(new ReadOnlySpan<byte>(h->appId.data, checked((int)h->appId.size)));
            app = nt is null ? null : paths.ToDosPath(nt);
        }

        var isV6 = (h->flags & FwpmNetEventFlags.IP_VERSION_SET) != 0 && h->ipVersion == 1;
        IPAddress? Address(FWP_ADDR_UNION* a) => isV6
            ? new IPAddress(new ReadOnlySpan<byte>(a->v6, 16))
            : NetEventDecoding.FromHostOrderV4(a->v4);

        IPEndPoint? local = (h->flags & FwpmNetEventFlags.LOCAL_ADDR_SET) != 0
            ? new IPEndPoint(Address(&h->localAddr)!, (h->flags & FwpmNetEventFlags.LOCAL_PORT_SET) != 0 ? h->localPort : 0)
            : null;
        IPEndPoint? remote = (h->flags & FwpmNetEventFlags.REMOTE_ADDR_SET) != 0
            ? new IPEndPoint(Address(&h->remoteAddr)!, (h->flags & FwpmNetEventFlags.REMOTE_PORT_SET) != 0 ? h->remotePort : 0)
            : null;

        var protocol = (h->flags & FwpmNetEventFlags.IP_PROTOCOL_SET) != 0 ? (ProtocolType)h->ipProtocol : ProtocolType.Unknown;
        return new BlockedConnection(h->timeStamp.ToDateTime(), app, protocol, local, remote, filterId, rule);
    }

    /// <summary>Removes every CrioFire filter, then the sublayer and provider.</summary>
    public void Uninstall()
    {
        ThrowIfDisposed();
        using var tx = BeginTransaction();
        {
            foreach (var filter in ListFilters())
            {
                DeleteFilter(filter.FilterId, ignoreMissing: true);
            }

            var subLayerKey = WfpIds.SubLayerKey;
            var result = Fwpuclnt.FwpmSubLayerDeleteByKey0(_handle, &subLayerKey);
            if (result != FwpErrors.FWP_E_SUBLAYER_NOT_FOUND)
            {
                Check("FwpmSubLayerDeleteByKey0", result);
            }

            var providerKey = WfpIds.ProviderKey;
            result = Fwpuclnt.FwpmProviderDeleteByKey0(_handle, &providerKey);
            if (result != FwpErrors.FWP_E_PROVIDER_NOT_FOUND)
            {
                Check("FwpmProviderDeleteByKey0", result);
            }
        }

        tx.Commit();
    }

    /// <summary>
    /// Sets the rule for one application, replacing any earlier CrioFire rule for the same
    /// app in the same direction. Returns the IDs of the filters added (one per IP version
    /// and direction).
    /// </summary>
    public IReadOnlyList<ulong> SetAppRule(string appPath, RuleAction action, TrafficDirection direction)
    {
        ThrowIfDisposed();
        ArgumentException.ThrowIfNullOrWhiteSpace(appPath);

        var fullPath = Path.GetFullPath(appPath);
        if (!File.Exists(fullPath))
        {
            throw new FileNotFoundException("No program at that path.", fullPath);
        }

        var layers = FilterLayers.For(direction);
        var description = new RuleDescription(action, direction, fullPath).Format();
        var name = $"CrioFire: {RuleDescription.ActionText(action)} {Path.GetFileName(fullPath)}";
        var added = new List<ulong>();

        FWP_BYTE_BLOB* appId = null;
        fixed (char* pPath = fullPath)
        {
            Check("FwpmGetAppIdFromFileName0", Fwpuclnt.FwpmGetAppIdFromFileName0(pPath, &appId));
        }

        try
        {
            using var tx = BeginTransaction();
            {
                RemoveAppRulesInternal(fullPath, layers);

                var providerKey = WfpIds.ProviderKey;
                fixed (char* pName = name)
                fixed (char* pDesc = description)
                {
                    foreach (var layer in layers)
                    {
                        var condition = new FWPM_FILTER_CONDITION0
                        {
                            fieldKey = WfpIds.ConditionAleAppId,
                            matchType = FWP_MATCH_TYPE.FWP_MATCH_EQUAL,
                            conditionValue = new FWP_VALUE0
                            {
                                type = FWP_DATA_TYPE.FWP_BYTE_BLOB_TYPE,
                                value = new FWP_VALUE_UNION { byteBlob = appId },
                            },
                        };

                        var filter = new FWPM_FILTER0
                        {
                            displayData = new FWPM_DISPLAY_DATA0 { name = pName, description = pDesc },
                            flags = FwpmFlags.FWPM_FILTER_FLAG_PERSISTENT,
                            providerKey = &providerKey,
                            layerKey = layer.Key,
                            subLayerKey = WfpIds.SubLayerKey,
                            weight = new FWP_VALUE0 { type = FWP_DATA_TYPE.FWP_EMPTY },
                            numFilterConditions = 1,
                            filterCondition = &condition,
                            action = new FWPM_ACTION0
                            {
                                type = action == RuleAction.Block ? FwpActionType.FWP_ACTION_BLOCK : FwpActionType.FWP_ACTION_PERMIT,
                            },
                        };

                        ulong id;
                        Check("FwpmFilterAdd0", Fwpuclnt.FwpmFilterAdd0(_handle, &filter, null, &id));
                        added.Add(id);
                    }
                }
            }

            tx.Commit();
        }
        finally
        {
            Fwpuclnt.FwpmFreeMemory0((void**)&appId);
        }

        return added;
    }

    /// <summary>Removes CrioFire's rules for one application in the given direction.</summary>
    public int RemoveAppRules(string appPath, TrafficDirection direction = TrafficDirection.Both)
    {
        ThrowIfDisposed();
        var fullPath = Path.GetFullPath(appPath);
        using var tx = BeginTransaction();
        var removed = RemoveAppRulesInternal(fullPath, FilterLayers.For(direction));
        tx.Commit();
        return removed;
    }

    /// <summary>Removes one CrioFire filter by ID. Refuses filters that CrioFire does not own.</summary>
    public void RemoveFilter(ulong filterId)
    {
        ThrowIfDisposed();
        using var tx = BeginTransaction();
        if (!ListFilters().Any(f => f.FilterId == filterId))
        {
            throw new InvalidOperationException($"Filter {filterId} does not belong to CrioFire, or does not exist.");
        }

        DeleteFilter(filterId, ignoreMissing: false);
        tx.Commit();
    }

    /// <summary>Recovery: removes every CrioFire filter (keeps provider and sublayer). Returns the count.</summary>
    public int RemoveAllFilters()
    {
        ThrowIfDisposed();
        using var tx = BeginTransaction();
        var filters = ListFilters();
        foreach (var filter in filters)
        {
            DeleteFilter(filter.FilterId, ignoreMissing: true);
        }

        tx.Commit();
        return filters.Count;
    }

    /// <summary>Lists the filters that belong to the criofire-provider.</summary>
    public IReadOnlyList<CrioFireFilter> ListFilters()
    {
        ThrowIfDisposed();
        var result = new List<CrioFireFilter>();

        IntPtr enumHandle;
        // A null template enumerates every filter; we keep only ours. Simple and layout-safe.
        Check("FwpmFilterCreateEnumHandle0", Fwpuclnt.FwpmFilterCreateEnumHandle0(_handle, null, &enumHandle));
        try
        {
            while (true)
            {
                FWPM_FILTER0** entries = null;
                uint count = 0;
                Check("FwpmFilterEnum0", Fwpuclnt.FwpmFilterEnum0(_handle, enumHandle, 256, &entries, &count));
                try
                {
                    for (var i = 0; i < count; i++)
                    {
                        var f = entries[i];
                        if (f->providerKey == null || *f->providerKey != WfpIds.ProviderKey)
                        {
                            continue;
                        }

                        var name = f->displayData.name == null ? string.Empty : new string(f->displayData.name);
                        var description = f->displayData.description == null ? null : new string(f->displayData.description);
                        var rule = RuleDescription.TryParse(description, out var parsed) ? parsed : null;
                        result.Add(new CrioFireFilter(f->filterId, name, FilterLayers.Find(f->layerKey), rule));
                    }
                }
                finally
                {
                    if (entries != null)
                    {
                        Fwpuclnt.FwpmFreeMemory0((void**)&entries);
                    }
                }

                if (count < 256)
                {
                    break;
                }
            }
        }
        finally
        {
            _ = Fwpuclnt.FwpmFilterDestroyEnumHandle0(_handle, enumHandle);
        }

        return result;
    }

    public void Dispose()
    {
        if (_handle != IntPtr.Zero)
        {
            _ = Fwpuclnt.FwpmEngineClose0(_handle);
            _handle = IntPtr.Zero;
        }
    }

    private int RemoveAppRulesInternal(string fullPath, IReadOnlyList<FilterLayer> layers)
    {
        var removed = 0;
        foreach (var filter in ListFilters())
        {
            if (filter.Rule is not null
                && filter.Layer is not null
                && layers.Contains(filter.Layer)
                && string.Equals(filter.Rule.AppPath, fullPath, StringComparison.OrdinalIgnoreCase))
            {
                DeleteFilter(filter.FilterId, ignoreMissing: true);
                removed++;
            }
        }

        return removed;
    }

    private void DeleteFilter(ulong filterId, bool ignoreMissing)
    {
        var result = Fwpuclnt.FwpmFilterDeleteById0(_handle, filterId);
        if (ignoreMissing && result == FwpErrors.FWP_E_FILTER_NOT_FOUND)
        {
            return;
        }

        Check("FwpmFilterDeleteById0", result);
    }

    private Transaction BeginTransaction()
    {
        Check("FwpmTransactionBegin0", Fwpuclnt.FwpmTransactionBegin0(_handle, 0));
        return new Transaction(_handle);
    }

    private void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(_handle == IntPtr.Zero, this);

    private static void Check(string operation, uint result)
    {
        if (result != FwpErrors.ERROR_SUCCESS)
        {
            throw new WfpException(operation, result);
        }
    }

    private static void CheckAllowExisting(string operation, uint result)
    {
        if (result != FwpErrors.FWP_E_ALREADY_EXISTS)
        {
            Check(operation, result);
        }
    }

    /// <summary>A BFE transaction: aborted on Dispose unless <see cref="Commit"/> ran.</summary>
    private sealed class Transaction(IntPtr handle) : IDisposable
    {
        private bool _done;

        public void Commit()
        {
            Check("FwpmTransactionCommit0", Fwpuclnt.FwpmTransactionCommit0(handle));
            _done = true;
        }

        public void Dispose()
        {
            if (!_done)
            {
                _ = Fwpuclnt.FwpmTransactionAbort0(handle);
                _done = true;
            }
        }
    }
}
