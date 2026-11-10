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

    // Filter weights inside CrioFire's sublayer (0-15): a user's rule beats the built-in permits,
    // which beat the catch-all block of Ask/Allow-list mode.
    private const byte RuleWeight = 10;
    private const byte BuiltInWeight = 5;
    private const byte DefaultBlockWeight = 0;

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

        using var appId = AppId.FromFile(fullPath);
        using var tx = BeginTransaction();
        var layers = FilterLayers.For(direction);
        RemoveAppRulesInternal(fullPath, layers);
        var added = AddAppRuleFilters(appId, fullPath, action, direction);
        tx.Commit();
        return added;
    }

    /// <summary>The current mode, read from the filters themselves (no default block = Learning).</summary>
    public FirewallMode GetMode()
    {
        ThrowIfDisposed();
        return ListFilters().FirstOrDefault(f => f.Kind == FilterKind.DefaultBlock)?.Mode ?? FirewallMode.Learning;
    }

    /// <summary>
    /// Switches the firewall mode. Ask and Allow-list add a catch-all outbound block (loopback is
    /// exempt) below the user's rules, plus built-in permits so Windows keeps working: services
    /// hosted in svchost.exe (DNS, DHCP, Windows Update) and the kernel ("System"). Learning removes
    /// them. Inbound traffic is left to Windows Firewall and per-app inbound rules.
    /// </summary>
    /// <param name="alsoAllow">
    /// Programs to give an outbound allow rule at the same time (programs that already have a
    /// CrioFire rule are left alone), e.g. the programs running right now.
    /// </param>
    public void SetMode(FirewallMode mode, IEnumerable<string>? alsoAllow = null)
    {
        ThrowIfDisposed();
        var existingRules = ListFilters()
            .Where(f => f.Rule is not null)
            .Select(f => f.Rule!.AppPath)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        var extraApps = new List<(AppId Id, string Path)>();
        try
        {
            foreach (var path in (alsoAllow ?? []).Select(Path.GetFullPath).Distinct(StringComparer.OrdinalIgnoreCase))
            {
                if (!existingRules.Contains(path) && File.Exists(path))
                {
                    try
                    {
                        extraApps.Add((AppId.FromFile(path), path));
                    }
                    catch (WfpException)
                    {
                        // A program we cannot resolve (e.g. on a removed drive) just gets no rule.
                    }
                }
            }

            using var tx = BeginTransaction();
            foreach (var filter in ListFilters().Where(f => f.Kind is FilterKind.DefaultBlock or FilterKind.BuiltInAllow))
            {
                DeleteFilter(filter.FilterId, ignoreMissing: true);
            }

            foreach (var (id, path) in extraApps)
            {
                AddAppRuleFilters(id, path, RuleAction.Allow, TrafficDirection.Outbound);
            }

            if (mode != FirewallMode.Learning)
            {
                var svchost = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "svchost.exe");
                using (var svchostId = AppId.FromFile(svchost))
                using (var systemId = AppId.ForKernel())
                {
                    foreach (var layer in new[] { FilterLayers.ConnectV4, FilterLayers.ConnectV6 })
                    {
                        AddAppIdFilter(layer, svchostId, "CrioFire: allow Windows services", FilterDescriptions.BuiltInAllow("svchost"), FwpActionType.FWP_ACTION_PERMIT, BuiltInWeight);
                        AddAppIdFilter(layer, systemId, "CrioFire: allow Windows kernel", FilterDescriptions.BuiltInAllow("system"), FwpActionType.FWP_ACTION_PERMIT, BuiltInWeight);
                    }
                }

                foreach (var layer in new[] { FilterLayers.ConnectV4, FilterLayers.ConnectV6 })
                {
                    var notLoopback = new FWPM_FILTER_CONDITION0
                    {
                        fieldKey = WfpIds.ConditionFlags,
                        matchType = FWP_MATCH_TYPE.FWP_MATCH_FLAGS_NONE_SET,
                        conditionValue = new FWP_VALUE0
                        {
                            type = FWP_DATA_TYPE.FWP_UINT32,
                            value = new FWP_VALUE_UNION { uint32 = FwpConditionFlags.FWP_CONDITION_FLAG_IS_LOOPBACK },
                        },
                    };
                    var name = mode == FirewallMode.Ask ? "CrioFire: block programs without a rule (ask)" : "CrioFire: block programs without a rule (allow-list)";
                    AddFilter(layer, name, FilterDescriptions.DefaultBlock(mode), FwpActionType.FWP_ACTION_BLOCK, DefaultBlockWeight, &notLoopback, 1);
                }
            }

            tx.Commit();
        }
        finally
        {
            foreach (var (id, _) in extraApps)
            {
                id.Dispose();
            }
        }
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

    /// <summary>
    /// Removes one CrioFire filter by ID; for a network rule, all of that rule's filters (one per
    /// layer). Refuses filters that CrioFire does not own. Returns how many filters were removed.
    /// </summary>
    public int RemoveFilter(ulong filterId)
    {
        ThrowIfDisposed();
        using var tx = BeginTransaction();
        var filters = ListFilters();
        var target = filters.FirstOrDefault(f => f.FilterId == filterId)
            ?? throw new InvalidOperationException($"Filter {filterId} does not belong to CrioFire, or does not exist.");

        var removed = 0;
        if (target.Net is { } net)
        {
            removed = RemoveNetRuleInternal(filters, net.Format());
        }
        else
        {
            DeleteFilter(filterId, ignoreMissing: false);
            removed = 1;
        }

        tx.Commit();
        return removed;
    }

    /// <summary>
    /// Adds a rule by port and/or remote address, optionally for one program, replacing an
    /// identical rule. One filter per matching layer: an IPv4-only address list adds no IPv6
    /// filters (an IPv6 filter without the address condition would match everything).
    /// </summary>
    public IReadOnlyList<ulong> AddNetRule(NetRule rule)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(rule);
        if (rule.AppPath is not null && !File.Exists(rule.AppPath))
        {
            throw new FileNotFoundException("No program at that path.", rule.AppPath);
        }

        using var appId = rule.AppPath is null ? null : AppId.FromFile(rule.AppPath);
        using var tx = BeginTransaction();
        var description = rule.Format();
        RemoveNetRuleInternal(ListFilters(), description);

        var name = $"CrioFire: {RuleDescription.ActionText(rule.Action)} {rule.Summary()}";
        var action = rule.Action == RuleAction.Block ? FwpActionType.FWP_ACTION_BLOCK : FwpActionType.FWP_ACTION_PERMIT;
        var added = new List<ulong>();
        foreach (var layer in FilterLayers.For(rule.Direction))
        {
            var v6 = layer == FilterLayers.ConnectV6 || layer == FilterLayers.RecvAcceptV6;
            var family = v6 ? System.Net.Sockets.AddressFamily.InterNetworkV6 : System.Net.Sockets.AddressFamily.InterNetwork;
            var addresses = rule.AddressList.Where(a => a.Family == family).ToList();
            if (rule.AddressList.Count > 0 && addresses.Count == 0)
            {
                continue;
            }

            added.Add(AddNetFilter(layer, rule, addresses, appId, name, description, action));
        }

        if (added.Count == 0)
        {
            throw new ArgumentException("None of the addresses can be used: give at least one IPv4 or IPv6 address.");
        }

        tx.Commit();
        return added;
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
                        var (kind, mode) = FilterDescriptions.Classify(description);
                        var net = kind == FilterKind.NetRule && NetRule.TryParse(description, out var parsedNet) ? parsedNet : null;
                        result.Add(new CrioFireFilter(f->filterId, name, FilterLayers.Find(f->layerKey), rule, kind, mode, net));
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

    private List<ulong> AddAppRuleFilters(AppId appId, string fullPath, RuleAction action, TrafficDirection direction)
    {
        var description = new RuleDescription(action, direction, fullPath).Format();
        var name = $"CrioFire: {RuleDescription.ActionText(action)} {Path.GetFileName(fullPath)}";
        var type = action == RuleAction.Block ? FwpActionType.FWP_ACTION_BLOCK : FwpActionType.FWP_ACTION_PERMIT;
        var added = new List<ulong>();
        foreach (var layer in FilterLayers.For(direction))
        {
            added.Add(AddAppIdFilter(layer, appId, name, description, type, RuleWeight));
        }

        return added;
    }

    private ulong AddAppIdFilter(FilterLayer layer, AppId appId, string name, string description, uint action, byte weight)
    {
        var condition = new FWPM_FILTER_CONDITION0
        {
            fieldKey = WfpIds.ConditionAleAppId,
            matchType = FWP_MATCH_TYPE.FWP_MATCH_EQUAL,
            conditionValue = new FWP_VALUE0
            {
                type = FWP_DATA_TYPE.FWP_BYTE_BLOB_TYPE,
                value = new FWP_VALUE_UNION { byteBlob = appId.Blob },
            },
        };
        return AddFilter(layer, name, description, action, weight, &condition, 1);
    }

    private ulong AddFilter(FilterLayer layer, string name, string description, uint action, byte weight, FWPM_FILTER_CONDITION0* conditions, uint conditionCount)
    {
        var providerKey = WfpIds.ProviderKey;
        fixed (char* pName = name)
        fixed (char* pDesc = description)
        {
            var filter = new FWPM_FILTER0
            {
                displayData = new FWPM_DISPLAY_DATA0 { name = pName, description = pDesc },
                flags = FwpmFlags.FWPM_FILTER_FLAG_PERSISTENT,
                providerKey = &providerKey,
                layerKey = layer.Key,
                subLayerKey = WfpIds.SubLayerKey,
                weight = new FWP_VALUE0 { type = FWP_DATA_TYPE.FWP_UINT8, value = new FWP_VALUE_UNION { uint8 = weight } },
                numFilterConditions = conditionCount,
                filterCondition = conditions,
                action = new FWPM_ACTION0 { type = action },
            };

            ulong id;
            Check("FwpmFilterAdd0", Fwpuclnt.FwpmFilterAdd0(_handle, &filter, null, &id));
            return id;
        }
    }

    private int RemoveNetRuleInternal(IReadOnlyList<CrioFireFilter> filters, string description)
    {
        var removed = 0;
        foreach (var filter in filters.Where(f => f.Net is not null && f.Net.Format() == description))
        {
            DeleteFilter(filter.FilterId, ignoreMissing: true);
            removed++;
        }

        return removed;
    }

    /// <summary>
    /// Builds one filter's conditions. WFP ORs conditions on the same field and ANDs different
    /// fields: (app) AND (protocol: tcp OR udp) AND (port: a OR b) AND (address: x OR y).
    /// </summary>
    private ulong AddNetFilter(FilterLayer layer, NetRule rule, List<AddressRange> addresses, AppId? appId, string name, string description, uint action)
    {
        byte[] protocols = rule.Protocol switch
        {
            NetProtocol.Tcp => [6],
            NetProtocol.Udp => [17],
            _ when rule.PortList.Count > 0 => [6, 17],   // ports only exist for TCP and UDP
            _ => [],
        };
        var ports = rule.PortList;
        var count = (appId is null ? 0 : 1) + protocols.Length + ports.Count + addresses.Count;
        var portField = layer.Direction == TrafficDirection.Outbound ? WfpIds.ConditionIpRemotePort : WfpIds.ConditionIpLocalPort;

        // Everything a condition points at must stay put until FwpmFilterAdd0 has copied it.
        var conditions = (FWPM_FILTER_CONDITION0*)NativeMemory.AllocZeroed((nuint)count, (nuint)sizeof(FWPM_FILTER_CONDITION0));
        var ranges = (FWP_RANGE0*)NativeMemory.AllocZeroed((nuint)Math.Max(1, ports.Count + addresses.Count), (nuint)sizeof(FWP_RANGE0));
        var v6Bytes = (byte*)NativeMemory.AllocZeroed((nuint)Math.Max(1, addresses.Count * 32));
        try
        {
            var i = 0;
            var r = 0;
            if (appId is not null)
            {
                conditions[i++] = new FWPM_FILTER_CONDITION0
                {
                    fieldKey = WfpIds.ConditionAleAppId,
                    matchType = FWP_MATCH_TYPE.FWP_MATCH_EQUAL,
                    conditionValue = new FWP_VALUE0 { type = FWP_DATA_TYPE.FWP_BYTE_BLOB_TYPE, value = new FWP_VALUE_UNION { byteBlob = appId.Blob } },
                };
            }

            foreach (var protocol in protocols)
            {
                conditions[i++] = new FWPM_FILTER_CONDITION0
                {
                    fieldKey = WfpIds.ConditionIpProtocol,
                    matchType = FWP_MATCH_TYPE.FWP_MATCH_EQUAL,
                    conditionValue = new FWP_VALUE0 { type = FWP_DATA_TYPE.FWP_UINT8, value = new FWP_VALUE_UNION { uint8 = protocol } },
                };
            }

            foreach (var port in ports)
            {
                var low = new FWP_VALUE0 { type = FWP_DATA_TYPE.FWP_UINT16, value = new FWP_VALUE_UNION { uint16 = port.Low } };
                if (port.Low == port.High)
                {
                    conditions[i++] = new FWPM_FILTER_CONDITION0 { fieldKey = portField, matchType = FWP_MATCH_TYPE.FWP_MATCH_EQUAL, conditionValue = low };
                }
                else
                {
                    ranges[r] = new FWP_RANGE0 { valueLow = low, valueHigh = new FWP_VALUE0 { type = FWP_DATA_TYPE.FWP_UINT16, value = new FWP_VALUE_UNION { uint16 = port.High } } };
                    conditions[i++] = new FWPM_FILTER_CONDITION0
                    {
                        fieldKey = portField,
                        matchType = FWP_MATCH_TYPE.FWP_MATCH_RANGE,
                        conditionValue = new FWP_VALUE0 { type = FWP_DATA_TYPE.FWP_RANGE_TYPE, value = new FWP_VALUE_UNION { rangeValue = &ranges[r] } },
                    };
                    r++;
                }
            }

            var a = 0;
            foreach (var address in addresses)
            {
                FWP_VALUE0 low, high;
                if (address.Family == System.Net.Sockets.AddressFamily.InterNetwork)
                {
                    low = new FWP_VALUE0 { type = FWP_DATA_TYPE.FWP_UINT32, value = new FWP_VALUE_UNION { uint32 = HostOrder(address.Low) } };
                    high = new FWP_VALUE0 { type = FWP_DATA_TYPE.FWP_UINT32, value = new FWP_VALUE_UNION { uint32 = HostOrder(address.High) } };
                }
                else
                {
                    var lowBytes = v6Bytes + (a * 32);
                    var highBytes = lowBytes + 16;
                    address.Low.GetAddressBytes().AsSpan().CopyTo(new Span<byte>(lowBytes, 16));
                    address.High.GetAddressBytes().AsSpan().CopyTo(new Span<byte>(highBytes, 16));
                    low = new FWP_VALUE0 { type = FWP_DATA_TYPE.FWP_BYTE_ARRAY16_TYPE, value = new FWP_VALUE_UNION { byteArray16 = lowBytes } };
                    high = new FWP_VALUE0 { type = FWP_DATA_TYPE.FWP_BYTE_ARRAY16_TYPE, value = new FWP_VALUE_UNION { byteArray16 = highBytes } };
                }

                a++;
                if (address.Low.Equals(address.High))
                {
                    conditions[i++] = new FWPM_FILTER_CONDITION0 { fieldKey = WfpIds.ConditionIpRemoteAddress, matchType = FWP_MATCH_TYPE.FWP_MATCH_EQUAL, conditionValue = low };
                }
                else
                {
                    ranges[r] = new FWP_RANGE0 { valueLow = low, valueHigh = high };
                    conditions[i++] = new FWPM_FILTER_CONDITION0
                    {
                        fieldKey = WfpIds.ConditionIpRemoteAddress,
                        matchType = FWP_MATCH_TYPE.FWP_MATCH_RANGE,
                        conditionValue = new FWP_VALUE0 { type = FWP_DATA_TYPE.FWP_RANGE_TYPE, value = new FWP_VALUE_UNION { rangeValue = &ranges[r] } },
                    };
                    r++;
                }
            }

            return AddFilter(layer, name, description, action, rule.Weight, conditions, (uint)count);
        }
        finally
        {
            NativeMemory.Free(conditions);
            NativeMemory.Free(ranges);
            NativeMemory.Free(v6Bytes);
        }
    }

    /// <summary>IPv4 address as WFP's FWP_UINT32: host byte order.</summary>
    private static uint HostOrder(System.Net.IPAddress address)
    {
        var b = address.GetAddressBytes();
        return ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3];
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

    /// <summary>A WFP application ID (FWP_BYTE_BLOB) that frees itself.</summary>
    private sealed class AppId : IDisposable
    {
        private readonly bool _fromWfp;

        private AppId(FWP_BYTE_BLOB* blob, bool fromWfp)
        {
            Blob = blob;
            _fromWfp = fromWfp;
        }

        public FWP_BYTE_BLOB* Blob { get; private set; }

        /// <summary>The NT-path app ID Windows uses for a program file.</summary>
        public static AppId FromFile(string fullPath)
        {
            FWP_BYTE_BLOB* blob = null;
            fixed (char* pPath = fullPath)
            {
                Check("FwpmGetAppIdFromFileName0", Fwpuclnt.FwpmGetAppIdFromFileName0(pPath, &blob));
            }

            return new AppId(blob, fromWfp: true);
        }

        /// <summary>The app ID of kernel-mode traffic: the UTF-16 string "System" with its terminator.</summary>
        public static AppId ForKernel()
        {
            const string text = "System\0";
            var size = text.Length * sizeof(char);
            var blob = (FWP_BYTE_BLOB*)System.Runtime.InteropServices.NativeMemory.Alloc((nuint)(sizeof(FWP_BYTE_BLOB) + size));
            blob->size = (uint)size;
            blob->data = (byte*)(blob + 1);
            fixed (char* p = text)
            {
                Buffer.MemoryCopy(p, blob->data, size, size);
            }

            return new AppId(blob, fromWfp: false);
        }

        public void Dispose()
        {
            if (Blob == null)
            {
                return;
            }

            if (_fromWfp)
            {
                var p = Blob;
                Fwpuclnt.FwpmFreeMemory0((void**)&p);
            }
            else
            {
                System.Runtime.InteropServices.NativeMemory.Free(Blob);
            }

            Blob = null;
        }
    }
}
