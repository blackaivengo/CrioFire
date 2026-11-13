using System.Runtime.InteropServices;
using Microsoft.CSharp.RuntimeBinder;

namespace CrioFire.Core;

/// <summary>A network this PC is connected to, and the kind Windows put it in.</summary>
public sealed record ConnectedNetwork(string Name, NetworkProfiles Kind);

/// <summary>
/// The networks this PC is on right now, from Windows' Network List Manager: what network-scoped
/// rules are matched against. Empty when Windows cannot tell (or not on Windows).
/// </summary>
public static class ConnectedNetworks
{
    private static readonly Guid NetworkListManager = new("DCB00C01-570F-4A9B-8D69-199FDBA5723B");

    public static IReadOnlyList<ConnectedNetwork> Current()
    {
        if (!OperatingSystem.IsWindows())
        {
            return [];
        }

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
                int category = network.GetCategory();
                list.Add(new ConnectedNetwork(name, FromCategory(category)));
            }

            return list;
        }
        catch (Exception ex) when (ex is COMException or RuntimeBinderException or InvalidCastException or UnauthorizedAccessException)
        {
            return [];
        }
    }

    /// <summary>NLM_NETWORK_CATEGORY: public 0, private 1, domain 2.</summary>
    public static NetworkProfiles FromCategory(int category) => category switch
    {
        2 => NetworkProfiles.Domain,
        1 => NetworkProfiles.Private,
        _ => NetworkProfiles.Public,
    };

    /// <summary>"Contoso-WiFi (public)", "Office (domain) and Home (private)", or "no network".</summary>
    public static string Describe(IReadOnlyList<ConnectedNetwork> networks)
    {
        ArgumentNullException.ThrowIfNull(networks);
        if (networks.Count == 0)
        {
            return "no network Windows recognizes";
        }

        var parts = networks.Select(n => $"{n.Name} ({NetworkScope.Text(n.Kind)})").ToList();
        return parts.Count == 1 ? parts[0] : string.Join(", ", parts.Take(parts.Count - 1)) + " and " + parts[^1];
    }
}
