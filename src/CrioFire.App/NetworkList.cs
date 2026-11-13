using System.Runtime.InteropServices;
using CrioFire.Core;
using Microsoft.CSharp.RuntimeBinder;

namespace CrioFire.App;

/// <summary>
/// The networks this PC is connected to right now and the kind Windows put each in, from Windows'
/// Network List Manager: what network-scoped rules are matched against. Empty when Windows cannot tell.
/// </summary>
internal static class NetworkList
{
    private static readonly Guid NetworkListManager = new("DCB00C01-570F-4A9B-8D69-199FDBA5723B");

    public static IReadOnlyList<ConnectedNetwork> Current()
    {
        try
        {
            var type = Type.GetTypeFromCLSID(NetworkListManager, throwOnError: false);
            if (type is null)
            {
                return [];
            }

            dynamic manager = Activator.CreateInstance(type)!;
            var list = new List<ConnectedNetwork>();
            foreach (var network in manager.GetNetworks(1))   // NLM_ENUM_NETWORK_CONNECTED
            {
                string name = network.GetName();
                int category = network.GetCategory();   // NLM_NETWORK_CATEGORY: public 0, private 1, domain 2
                list.Add(new ConnectedNetwork(name, ConnectedNetworks.FromCategory(category)));
            }

            return list;
        }
        catch (Exception ex) when (ex is COMException or RuntimeBinderException or InvalidCastException or UnauthorizedAccessException)
        {
            return [];
        }
    }
}
