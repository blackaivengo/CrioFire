namespace CrioFire.Core;

/// <summary>
/// Well-known GUIDs. CrioFire's own keys never change once released:
/// they are how CrioFire finds its objects in the Base Filtering Engine.
/// </summary>
public static class WfpIds
{
    /// <summary>The criofire-provider key. Every CrioFire filter points at this provider.</summary>
    public static readonly Guid ProviderKey = new("4e193e29-b3c2-4427-87b8-2d5a349111c4");

    /// <summary>The criofire-sublayer key. All CrioFire filters live in this sublayer.</summary>
    public static readonly Guid SubLayerKey = new("96ba80d3-6072-4fca-8f6e-cb2f06ae8d7f");

    // Windows SDK values (fwpmu.h). Outbound connections are authorized at ALE_AUTH_CONNECT,
    // inbound ones at ALE_AUTH_RECV_ACCEPT; each exists once for IPv4 and once for IPv6.

    /// <summary>FWPM_LAYER_ALE_AUTH_CONNECT_V4.</summary>
    public static readonly Guid LayerAleAuthConnectV4 = new("c38d57d1-05a7-4c33-904f-7fbceee60e82");

    /// <summary>FWPM_LAYER_ALE_AUTH_CONNECT_V6.</summary>
    public static readonly Guid LayerAleAuthConnectV6 = new("4a72393b-319f-44bc-84c3-ba54dcb3b6b4");

    /// <summary>FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4.</summary>
    public static readonly Guid LayerAleAuthRecvAcceptV4 = new("e1cd9fe7-f4b5-4273-96c0-592e487b8650");

    /// <summary>FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6.</summary>
    public static readonly Guid LayerAleAuthRecvAcceptV6 = new("a3b42c97-9f04-4672-b87e-cee9c483257f");

    /// <summary>FWPM_CONDITION_FLAGS: per-connection flags such as FWP_CONDITION_FLAG_IS_LOOPBACK.</summary>
    public static readonly Guid ConditionFlags = new("632ce23b-5167-435c-86d7-e903684aa80c");

    /// <summary>FWPM_CONDITION_IP_PROTOCOL: the IP protocol number (6 = TCP, 17 = UDP). FWP_UINT8.</summary>
    public static readonly Guid ConditionIpProtocol = new("3971ef2b-623e-4f9a-8cb1-6e79b806b9a7");

    /// <summary>FWPM_CONDITION_IP_REMOTE_ADDRESS: FWP_UINT32 (IPv4, host order) or FWP_BYTE_ARRAY16 (IPv6).</summary>
    public static readonly Guid ConditionIpRemoteAddress = new("b235ae9a-1d64-49b8-a44c-5ff3d9095045");

    /// <summary>FWPM_CONDITION_IP_LOCAL_PORT. FWP_UINT16.</summary>
    public static readonly Guid ConditionIpLocalPort = new("0c1ba1af-5765-453f-af22-a8f791ac775b");

    /// <summary>FWPM_CONDITION_IP_REMOTE_PORT. FWP_UINT16.</summary>
    public static readonly Guid ConditionIpRemotePort = new("c35a604d-d22b-4e1a-91b4-68f674ee674b");

    /// <summary>FWPM_CONDITION_ALE_APP_ID: the application's NT device path.</summary>
    public static readonly Guid ConditionAleAppId = new("d78e1e87-8644-4ea5-9437-d809ecefc971");

    /// <summary>FWPM_CONDITION_ALE_USER_ID: the process token, matched against a security descriptor (e.g. a service SID).</summary>
    public static readonly Guid ConditionAleUserId = new("af043a0a-b34d-4f86-979c-c90371af6e66");
}
