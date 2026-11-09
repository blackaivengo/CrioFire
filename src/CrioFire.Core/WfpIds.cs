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

    /// <summary>FWPM_CONDITION_ALE_APP_ID: the application's NT device path.</summary>
    public static readonly Guid ConditionAleAppId = new("d78e1e87-8644-4ea5-9437-d809ecefc971");
}
