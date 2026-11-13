namespace CrioFire.Core;

/// <summary>A network this PC is connected to, and the kind Windows put it in.</summary>
public sealed record ConnectedNetwork(string Name, NetworkProfiles Kind);

/// <summary>
/// The kinds of the networks this PC is on, in words. The app reads the networks themselves from
/// Windows' Network List Manager (a COM call kept out of this AOT-compatible library).
/// </summary>
public static class ConnectedNetworks
{
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
