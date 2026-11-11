using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Media3D;
using CrioFire.App.Pages;
using CrioFire.Core;

namespace CrioFire.App;

/// <summary>
/// What a right-clicked row is about: a program (or the kernel), one Windows service, a remote
/// address, and for Activity rows the recorded connection itself.
/// </summary>
internal sealed record MenuTarget(string? App, string? Service = null, string? Remote = null, int Port = 0, TrafficItem? Item = null)
{
    /// <summary>The single Windows service behind it, if exactly one is known.</summary>
    public string? OneService =>
        (Service ?? string.Empty).Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries) is [var one] ? one : null;

    /// <summary>"service Dnscache", "chat.exe", "Windows services (svchost.exe)", or the address.</summary>
    public string Who => OneService is { } service ? $"service {service}"
        : App is not null ? Pages.Who.Of(App, Service).Name
        : Remote ?? "this connection";

    /// <summary>The connection as the rule actions expect it; made up for rows that are not recorded connections.</summary>
    public TrafficItem AsItem() => Item ?? new TrafficItem(
        true, DateTime.UtcNow, DateTime.UtcNow, App, Service, null, "out", Remote, Port, null, null, 0, 1);

    /// <summary>"203.0.113.5:443" or "[2001:db8::1]:443" parsed into address and port.</summary>
    public static (string? Address, int Port) SplitEndpoint(string? text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return (null, 0);
        }

        if (IPEndPoint.TryParse(text, out var endpoint))
        {
            return (endpoint.Address.ToString(), endpoint.Port);
        }

        return (text, 0);
    }
}

/// <summary>Everything known about a program, service or connection, as labelled lines.</summary>
internal static class ConnectionFacts
{
    private static readonly Dictionary<string, string> HostNames = [];

    /// <summary>True when the host name of this address has not been looked up yet.</summary>
    public static bool NeedsLookup(string? address) =>
        address is not null && !HostNames.ContainsKey(address) && NetworkFacts.AddressScope(address) is not ("unknown" or "this PC (loopback)");

    /// <summary>Reverse DNS for an address, once; at most 4 seconds.</summary>
    public static async Task LookUpAsync(string address)
    {
        HostNames[address] = string.Empty;
        try
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(4));
            var entry = await Dns.GetHostEntryAsync(address, timeout.Token);
            HostNames[address] = entry.HostName == address ? string.Empty : entry.HostName;
        }
        catch (Exception ex) when (ex is SocketException or OperationCanceledException or ArgumentException)
        {
            // No name: leave it empty.
        }
    }

    public static List<Fact> For(MenuTarget t, AppModel model)
    {
        var c = CultureInfo.CurrentCulture;
        var facts = new List<Fact>();
        var i = t.Item;
        var inbound = i?.Direction == "in";
        if (i is not null)
        {
            var times = i.Count == 1 ? "once" : $"{Fmt.Count(i.Count)} times";
            var span = i.FirstUtc == i.LastUtc
                ? i.LastUtc.ToLocalTime().ToString("g", c)
                : $"{i.FirstUtc.ToLocalTime().ToString("g", c)} – {i.LastUtc.ToLocalTime().ToString("g", c)}";
            facts.Add(new Fact("Connection", $"{(inbound ? "Inbound (another machine connected to this PC)" : "Outbound (this PC connected out)")}, {i.Protocol ?? "?"}, {times}: {span}"));
        }

        if (t.Remote is { } remote)
        {
            var host = HostNames.TryGetValue(remote, out var name)
                ? (name.Length == 0 ? "no host name found" : name)
                : NetworkFacts.AddressScope(remote) == "this PC (loopback)" ? "this PC" : "looking up the host name…";
            facts.Add(new Fact(inbound ? "From" : "To", $"{remote} · {NetworkFacts.AddressScope(remote)} · {host}"));
        }

        if (t.Port > 0)
        {
            var known = NetworkFacts.PortName(t.Port) ?? "no well-known service";
            facts.Add(new Fact(inbound ? "Port on this PC" : "Port on the other side", $"{t.Port} ({known})"));
        }

        if (i?.Local is { } local)
        {
            facts.Add(new Fact("Local address and port", inbound ? local : $"{local} (Windows picks this source port for each new connection)"));
        }

        if (i is not null)
        {
            facts.Add(new Fact(i.Allowed ? "Why it was allowed" : "Why it was blocked",
                i.WhyLabel + (i.FilterId != 0 ? $" · CrioFire filter {i.FilterId}" : string.Empty)));
        }

        if (t.App is not null || i is not null)
        {
            facts.Add(new Fact("Program", Program(t.App)));
        }

        if (t.Service is { } services)
        {
            var all = WindowsServiceList.Read().ToDictionary(s => s.Name, s => s.DisplayName, StringComparer.OrdinalIgnoreCase);
            facts.Add(new Fact("Windows service", string.Join(", ", services.Split(',', StringSplitOptions.TrimEntries)
                .Select(s => all.TryGetValue(s, out var display) ? $"{display} ({s})" : s))));
        }

        if (t.App is not null || t.Service is not null)
        {
            facts.Add(new Fact("Rules for it", Rules(t, model)));
            facts.Add(new Fact("Right now", Live(t.App)));
        }

        return facts;
    }

    public static string AsText(string title, string? subtitle, IEnumerable<Fact> facts) =>
        string.Join(Environment.NewLine, new[] { title, subtitle }.Where(s => !string.IsNullOrEmpty(s))
            .Concat(facts.Select(f => $"{f.Label}: {f.Value}")));

    private static string Program(string? app)
    {
        if (string.IsNullOrEmpty(app))
        {
            return "Unknown: Windows did not report a program.";
        }

        if (KnownApps.IsKernel(app))
        {
            return "The Windows kernel: file and printer sharing, NetBIOS, ICMP and other system traffic.";
        }

        if (!File.Exists(app))
        {
            return $"{app} (not found on this PC any more)";
        }

        try
        {
            var v = FileVersionInfo.GetVersionInfo(app);
            var parts = new[] { v.FileDescription, v.CompanyName, string.IsNullOrWhiteSpace(v.FileVersion) ? null : $"version {v.FileVersion}" }
                .Where(p => !string.IsNullOrWhiteSpace(p))
                .ToList();
            return parts.Count == 0 ? "No description in the file." : string.Join(" · ", parts);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return "Could not read the file's details.";
        }
    }

    private static string Rules(MenuTarget t, AppModel model)
    {
        var lines = new List<string>();
        foreach (var r in model.Rules)
        {
            var program = (r.Kind == nameof(FilterKind.AppRule) || r.Kind == nameof(FilterKind.NetRule)) && t.App is not null
                && string.Equals(r.App, t.App, StringComparison.OrdinalIgnoreCase);
            var service = r.Kind == nameof(FilterKind.ServiceRule) && t.Service is not null && r.Service is not null
                && t.Service.Split(',', StringSplitOptions.TrimEntries).Contains(r.Service, StringComparer.OrdinalIgnoreCase);
            if (program || service)
            {
                var text = r.Summary ?? $"{r.Action} {r.Direction}" + (service ? $" (service {r.Service})" : string.Empty);
                if (!lines.Contains(text))
                {
                    lines.Add(text);
                }
            }
        }

        return lines.Count == 0 ? $"None. The mode decides ({AppModel.ModeName(model.Mode)} mode)." : string.Join("\n", lines);
    }

    private static string Live(string? app)
    {
        if (string.IsNullOrEmpty(app))
        {
            return "–";
        }

        var live = ConnectionTable.Read()
            .Where(c => KnownApps.IsKernel(app) ? c.ProcessId == 4 : string.Equals(c.ProcessPath, app, StringComparison.OrdinalIgnoreCase))
            .ToList();
        if (live.Count == 0)
        {
            return "No open connections or listening ports.";
        }

        var pids = string.Join(", ", live.Select(c => c.ProcessId).Distinct().Order());
        var listening = live.Count(c => c.Remote is null);
        return $"{live.Count - listening} open connections, {listening} listening ports · process {pids}";
    }
}

/// <summary>
/// The right-click menu for rows of connections: allow, block, details, the program's connections,
/// its file location, the remote address, and copying. Built for the row under the mouse (or the
/// selected row, from the keyboard); with several rows selected, allow and block apply to all.
/// </summary>
internal static class RowMenu
{
    /// <param name="convert">Turns a row's data into a target, or null for rows without a menu.</param>
    /// <param name="selection">For lists with multi-select: the selected connections.</param>
    public static void Attach(FrameworkElement list, AppModel model, Func<object, MenuTarget?> convert, Func<IReadOnlyList<TrafficItem>>? selection = null)
    {
        var menu = new ContextMenu();
        list.ContextMenu = menu;
        list.ContextMenuOpening += (_, e) =>
        {
            var target = Find(e.OriginalSource as DependencyObject, list, convert);
            var owner = Window.GetWindow(list);
            if (target is null || owner is null)
            {
                e.Handled = true;   // no menu on headers and empty space
                return;
            }

            var selected = selection?.Invoke() ?? [];
            menu.Items.Clear();
            Fill(menu, model, owner, target, selected.Count > 1 ? selected : null);
        };
    }

    /// <summary>Targets for the row types that show programs and connections.</summary>
    public static MenuTarget? From(object data) => data switch
    {
        TrafficRow r => new MenuTarget(r.Item.App, r.Item.Service, r.Item.Remote, r.Item.Port, r.Item),
        LiveRow l => FromLive(l),
        AllowedRow a => new MenuTarget(a.App, a.Service),
        ShareRow s when !string.IsNullOrEmpty(s.App) => new MenuTarget(s.App),
        ProgramRow p when !string.IsNullOrEmpty(p.App) => new MenuTarget(p.App),
        PendingAlert p => FromEndpoint(p.Event.App, p.Event.Remote),
        DestinationRow d => new MenuTarget(null, null, d.Address, int.TryParse(d.Port, NumberStyles.None, CultureInfo.InvariantCulture, out var port) ? port : 0),
        _ => null,
    };

    private static MenuTarget FromLive(LiveRow l)
    {
        var app = l.ProcessId == 4 ? KnownApps.Kernel : Path.IsPathRooted(l.Path) ? l.Path : null;
        var (address, port) = MenuTarget.SplitEndpoint(l.Remote);
        return new MenuTarget(app, l.Services.Length == 0 ? null : l.Services, address, port);
    }

    private static MenuTarget FromEndpoint(string? app, string? remote)
    {
        var (address, port) = MenuTarget.SplitEndpoint(remote);
        return new MenuTarget(app, null, address, port);
    }

    private static MenuTarget? Find(DependencyObject? source, DependencyObject list, Func<object, MenuTarget?> convert)
    {
        for (var d = source; d is not null && d != list; d = d is Visual or Visual3D ? VisualTreeHelper.GetParent(d) : LogicalTreeHelper.GetParent(d))
        {
            if (d is FrameworkElement { DataContext: { } data } && convert(data) is { } target)
            {
                return target;
            }
        }

        return null;
    }

    private static void Fill(ContextMenu menu, AppModel model, Window owner, MenuTarget t, IReadOnlyList<TrafficItem>? many)
    {
        var title = many is not null ? $"{many.Count} selected rows" : t.Who;
        menu.Items.Add(new MenuItem { Header = title, IsHitTestVisible = false, Focusable = false, FontWeight = FontWeights.SemiBold });

        if (many is not null)
        {
            menu.Items.Add(Item($"Allow all {many.Count}", () => model.ApplyToMany(owner, many, "allow")));
            menu.Items.Add(Item($"Allow all {many.Count} for 1 hour", () => model.ApplyToMany(owner, many, "allow", 60)));
            menu.Items.Add(Item($"Block all {many.Count}", () => model.ApplyToMany(owner, many, "block"), danger: true));
            menu.Items.Add(new Separator());
        }
        else if (t.App is not null)
        {
            var item = t.AsItem();
            var isService = KnownApps.IsServiceHost(t.App);
            var unblock = t.Item is { Allowed: false } ? "Unblock" : "Allow";
            menu.Items.Add(Item($"{unblock} {t.Who}", () => model.ApplyToMany(owner, [item], "allow")));
            menu.Items.Add(Item($"Allow {t.Who} for 1 hour", () => model.ApplyToMany(owner, [item], "allow", 60), enabled: !isService));
            menu.Items.Add(Item($"Block {t.Who}", () => model.ApplyToMany(owner, [item], "block"), danger: true));

            var hasRules = t.OneService is { } svc
                ? model.Rules.Any(r => r.Kind == nameof(FilterKind.ServiceRule) && string.Equals(r.Service, svc, StringComparison.OrdinalIgnoreCase))
                : model.Rules.Any(r => r.Kind == nameof(FilterKind.AppRule) && string.Equals(r.App, t.App, StringComparison.OrdinalIgnoreCase));
            if (hasRules)
            {
                menu.Items.Add(Item($"Remove the rules for {t.Who}", () =>
                {
                    if (t.OneService is { } s)
                    {
                        model.RemoveServiceRules(s);
                    }
                    else
                    {
                        model.RemoveRules(t.App!);
                    }
                }));
            }

            menu.Items.Add(new Separator());
        }

        menu.Items.Add(Item("More info…", () => DetailsWindow.Open(owner, model, t)));
        if (t.App is not null)
        {
            menu.Items.Add(Item("Show all its connections", () => model.OpenActivity(t.OneService is { } s
                ? new ActivityQuery("all", Service: s)
                : new ActivityQuery("all", App: t.App))));
            menu.Items.Add(Item("Open file location", () => OpenFolder(t.App), enabled: File.Exists(t.App)));
        }

        if (t.Remote is { } remote)
        {
            var scope = NetworkFacts.AddressScope(remote);
            menu.Items.Add(new Separator());
            menu.Items.Add(Item($"Show connections with {remote}", () => model.OpenActivity(new ActivityQuery("all", Search: remote))));
            menu.Items.Add(Item($"Block {remote} for every program…", () => BlockAddress(model, owner, remote),
                enabled: scope is not ("this PC (loopback)" or "unknown"), danger: true));
            menu.Items.Add(Item($"Look up {remote} online", () => Browse($"https://ipinfo.io/{remote}"), enabled: scope == "internet"));
        }

        menu.Items.Add(new Separator());
        if (t.App is not null)
        {
            menu.Items.Add(Item("Copy program path", () => Copy(model, t.App)));
        }

        if (t.Remote is not null)
        {
            menu.Items.Add(Item("Copy address", () => Copy(model, t.Port > 0 ? $"{t.Remote}:{t.Port}" : t.Remote)));
        }

        menu.Items.Add(Item("Copy details", () => Copy(model, ConnectionFacts.AsText(t.Who, t.App, ConnectionFacts.For(t, model)))));
    }

    private static MenuItem Item(string header, Action action, bool enabled = true, bool danger = false)
    {
        var item = new MenuItem { Header = header, IsEnabled = enabled };
        if (danger)
        {
            item.SetResourceReference(Control.ForegroundProperty, "FireTextBrush");
        }

        item.Click += (_, _) => action();
        return item;
    }

    private static void BlockAddress(AppModel model, Window owner, string address)
    {
        var choice = ChoiceDialog.Ask(owner, $"Block {address}?",
            $"No program on this PC will be able to connect to {address}, and it will not be able to connect to this PC. You can remove the rule under Rules → Network rules.",
            [$"Block {address}", "Cancel"], defaultIndex: 0, danger: true);
        if (choice != 0)
        {
            return;
        }

        if (NetRule.Create(RuleAction.Block, TrafficDirection.Both, NetProtocol.Any, null, address, null, out var error) is { } rule)
        {
            model.AddNetRule(rule);
        }
        else
        {
            model.Say(error);
        }
    }

    public static void OpenFolder(string? app)
    {
        if (app is not null && File.Exists(app))
        {
            Process.Start(new ProcessStartInfo("explorer.exe", $"/select,\"{app}\"") { UseShellExecute = true });
        }
    }

    private static void Browse(string url) => Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });

    public static void Copy(AppModel model, string text)
    {
        try
        {
            Clipboard.SetText(text);
            model.Say("Copied.");
        }
        catch (System.Runtime.InteropServices.ExternalException)
        {
            model.Say("The clipboard is busy; try again.");
        }
    }
}
