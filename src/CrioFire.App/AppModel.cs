using System.Collections.ObjectModel;
using System.Globalization;
using System.IO;
using System.Windows;
using System.Windows.Media;
using CrioFire.Core;
using CrioFire.Core.Api;

namespace CrioFire.App;

/// <summary>Short-lived calls to the criofire service; failures become a message for the user.</summary>
internal static class Service
{
    public static ApiResponse? Call(ApiRequest request, out string? error)
    {
        try
        {
            using var client = CrioFireClient.TryConnect(timeoutMs: 500);
            if (client is null)
            {
                error = "The CrioFire service is not running. Start it with 'sc start criofire' from an administrator prompt.";
                return null;
            }

            var response = client.Send(request);
            error = response.Ok ? null : response.Error;
            return response.Ok ? response : null;
        }
        catch (IOException ex)
        {
            error = $"Lost the connection to the CrioFire service: {ex.Message}";
            return null;
        }
    }
}

/// <summary>A program the Ask mode stopped, waiting for the user's decision.</summary>
internal sealed record PendingAlert(EventInfo Event)
{
    public string App => Event.App ?? "?";

    public string Name => Path.GetFileName(Event.App) ?? "A program";

    public string Detail => $"{Event.Protocol} → {Event.Remote ?? "unknown address"} · {Event.App}";
}

/// <summary>
/// What every page shares: the latest status and rules, programs waiting for a decision, and the
/// actions that change the firewall. Pages call <see cref="RefreshCore"/> and the write methods;
/// <see cref="Changed"/> tells the shell to refresh what is on screen.
/// </summary>
internal sealed class AppModel
{
    private bool _showAllowed;

    public StatusInfo? Status { get; private set; }

    public IReadOnlyList<RuleInfo> Rules { get; private set; } = [];

    /// <summary>CrioFire's automatic permits (Windows services, Windows kernel) and whether they are on.</summary>
    public IReadOnlyList<AutoRuleInfo> AutoRules { get; private set; } = [];

    public ObservableCollection<PendingAlert> Pending { get; } = [];

    public string? Error { get; private set; }

    public string Mode => Status?.Mode ?? "learning";

    public event EventHandler? Changed;

    public event EventHandler<string?>? Message;

    /// <summary>A page asks the shell to open another page (by its sidebar name).</summary>
    public event EventHandler<string>? NavigateRequested;

    /// <summary>A program waiting for a decision got one; the shell closes its alert.</summary>
    public event EventHandler<string>? PendingResolved;

    /// <summary>App rules, one entry per program/action/direction rather than per IPv4/IPv6 filter.</summary>
    public IEnumerable<RuleInfo> AppRules => Rules
        .Where(r => r.Kind == nameof(FilterKind.AppRule))
        .GroupBy(r => (r.App?.ToUpperInvariant(), r.Action, r.Direction))
        .Select(g => g.First());

    /// <summary>Network rules (port/address), one entry per rule rather than per filter.</summary>
    public IEnumerable<RuleInfo> NetRules => Rules
        .Where(r => r.Kind == nameof(FilterKind.NetRule))
        .GroupBy(r => (r.Action, r.Direction, r.Protocol, r.Ports, r.Addresses, r.App?.ToUpperInvariant()))
        .Select(g => g.First());

    /// <summary>Service rules, one entry per service/action/direction.</summary>
    public IEnumerable<RuleInfo> ServiceRules => Rules
        .Where(r => r.Kind == nameof(FilterKind.ServiceRule))
        .GroupBy(r => (r.Service?.ToUpperInvariant(), r.Action, r.Direction))
        .Select(g => g.First());

    public bool SetServiceRule(string service, string action, string direction = "out")
    {
        var ok = Call(new ApiRequest { Op = ApiOps.SetServiceRule, Service = service, Action = action, Direction = direction }) is not null;
        if (ok)
        {
            Message?.Invoke(this, action == "allow" ? $"Allowed the service {service}." : $"Blocked the service {service}.");
            NotifyChanged();
        }

        return ok;
    }

    public bool RemoveServiceRules(string service)
    {
        var ok = Call(new ApiRequest { Op = ApiOps.RemoveServiceRules, Service = service }) is not null;
        if (ok)
        {
            Message?.Invoke(this, $"Removed the rules for the service {service}.");
            NotifyChanged();
        }

        return ok;
    }

    /// <summary>Switches an automatic permit on or off; turning one off is confirmed first.</summary>
    public bool SetAutoRule(Window owner, string name, bool enabled)
    {
        var what = AutoRuleName(name);
        if (!enabled)
        {
            var warning = name == AutoRulePolicy.WindowsServices
                ? "Windows services such as DNS (name lookups), DHCP and Windows Update will need their own rules. Until you add them, programs without a rule may not reach anything by name.

Tip: block or allow single services under Rules instead."
                : "Kernel traffic such as file and printer sharing (SMB) and NetBIOS will need its own rule.";
            var choice = ChoiceDialog.Ask(owner, $"Stop allowing {what} automatically?", warning + "

This applies in Ask and Allow-list modes.",
                ["Stop allowing automatically", "Cancel"], defaultIndex: 1, danger: true);
            if (choice != 0)
            {
                NotifyChanged();
                return false;
            }
        }

        var result = Call(new ApiRequest { Op = ApiOps.SetAutoRule, AutoRule = name, Enabled = enabled });
        if (result is not null)
        {
            AutoRules = result.AutoRules ?? AutoRules;
            Message?.Invoke(this, enabled ? $"{what} are allowed automatically again." : $"{what} are no longer allowed automatically.");
        }

        RefreshCore();
        NotifyChanged();
        return result is not null;
    }

    public static string AutoRuleName(string name) =>
        name == AutoRulePolicy.WindowsKernel ? "Windows kernel connections" : "Windows services";

    /// <summary>
    /// Allows or blocks whatever made a connection: a program, the Windows kernel, or one service in
    /// svchost.exe. Blocking all of svchost.exe would cut off DNS, so it is only done when asked twice.
    /// </summary>
    public bool Decide(Window owner, string? app, string? services, string action)
    {
        if (string.IsNullOrEmpty(app))
        {
            Say("CrioFire could not tell which program made this connection.");
            return false;
        }

        if (!KnownApps.IsServiceHost(app))
        {
            return SetRule(app, action);
        }

        var names = (services ?? string.Empty).Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        var verb = action == "allow" ? "Allow" : "Block";
        if (names.Length == 1)
        {
            return SetServiceRule(names[0], action);
        }

        var choices = names.Select(n => $"{verb} the service {n}").ToList();
        choices.Add("Choose a service...");
        choices.Add($"{verb} every Windows service (svchost.exe)");
        choices.Add("Cancel");
        var message = names.Length == 0
            ? "This connection came from svchost.exe, which runs many Windows services, and the socket was already closed so CrioFire could not tell which service it was. Pick the service, or look for it under Live connections while it is connected."
            : "This connection came from a svchost.exe process that runs several services. Which one?";
        var choice = ChoiceDialog.Ask(owner, $"{verb} a Windows service", message, choices, defaultIndex: 0, danger: action == "block");
        if (choice is null || choice == choices.Count - 1)
        {
            return false;
        }

        if (choice < names.Length)
        {
            return SetServiceRule(names[choice.Value], action);
        }

        if (choice == names.Length)
        {
            return ServiceRuleDialog.Ask(owner, null, action) is { } picked && SetServiceRule(picked.Service, picked.Action, picked.Direction);
        }

        if (action == "block" && ChoiceDialog.Ask(owner, "Block every Windows service?",
                "DNS, DHCP, Windows Update and dozens of other services will lose network access, and programs will no longer find anything by name. Undo it under Rules.",
                ["Block svchost.exe", "Cancel"], defaultIndex: 1, danger: true) != 0)
        {
            return false;
        }

        return SetRule(app, action);
    }

    public bool AddNetRule(NetRule rule)
    {
        var ok = Call(new ApiRequest
        {
            Op = ApiOps.AddNetRule,
            Action = RuleDescription.ActionText(rule.Action),
            Direction = RuleDescription.DirectionText(rule.Direction),
            Protocol = NetRule.ProtocolText(rule.Protocol),
            Ports = rule.Ports,
            Addresses = rule.Addresses,
            App = rule.AppPath,
        }) is not null;
        if (ok)
        {
            Message?.Invoke(this, $"{(rule.Action == RuleAction.Block ? "Blocking" : "Allowing")} {rule.Summary()}.");
            NotifyChanged();
        }

        return ok;
    }

    /// <summary>Removes a network rule (all its filters) by the ID of any one of its filters.</summary>
    public bool RemoveNetRule(ulong filterId, string what)
    {
        var ok = Call(new ApiRequest { Op = ApiOps.RemoveFilter, FilterId = filterId }) is not null;
        if (ok)
        {
            Message?.Invoke(this, $"Removed the rule for {what}.");
            NotifyChanged();
        }

        return ok;
    }

    public bool RefreshCore()
    {
        var status = Service.Call(new ApiRequest { Op = ApiOps.Status }, out var error);
        Status = status?.Status;
        if (status is not null)
        {
            var list = Service.Call(new ApiRequest { Op = ApiOps.List }, out error);
            Rules = list?.Rules ?? [];
            AutoRules = list?.AutoRules ?? [];
        }

        Error = error;
        return status is not null;
    }

    public ApiResponse? Call(ApiRequest request)
    {
        var result = Service.Call(request, out var error);
        if (result is null)
        {
            Message?.Invoke(this, error);
        }

        return result;
    }

    public bool SetRule(string app, string action, int? expiresMinutes = null)
    {
        var ok = Call(new ApiRequest { Op = ApiOps.SetRule, App = app, Action = action, ExpiresMinutes = expiresMinutes }) is not null;
        if (ok)
        {
            Resolve(app);
            var name = KnownApps.DisplayName(app);
            Message?.Invoke(this, action == "allow"
                ? (expiresMinutes is int m ? $"Allowed {name} for {m} minutes." : $"Allowed {name}.")
                : $"Blocked {name}.");
            NotifyChanged();
        }

        return ok;
    }

    public bool RemoveRules(string app)
    {
        var ok = Call(new ApiRequest { Op = ApiOps.RemoveRules, App = app }) is not null;
        if (ok)
        {
            Message?.Invoke(this, $"Removed the rules for {KnownApps.DisplayName(app)}.");
            NotifyChanged();
        }

        return ok;
    }

    /// <summary>
    /// Switches mode. Blocking modes first offer to allow everything running, then must be
    /// confirmed within 60 seconds or CrioFire switches back.
    /// </summary>
    public bool SetMode(Window owner, string mode)
    {
        var previous = Mode;
        if (mode == previous)
        {
            return true;
        }

        List<string>? running = null;
        if (mode != "learning")
        {
            var choice = ChoiceDialog.Ask(
                owner,
                "Switch to a blocking mode",
                "Programs without an allow rule will no longer be able to connect out.\n\nAlso allow every program that is running right now? This is the easy way to start.",
                ["Allow running programs", "Don't allow them", "Cancel"],
                defaultIndex: 0);
            if (choice is null or 2)
            {
                NotifyChanged();
                return false;
            }

            if (choice == 0)
            {
                running = RunningPrograms();
            }
        }

        if (Call(new ApiRequest { Op = ApiOps.SetMode, Mode = mode, Apps = running }) is null)
        {
            NotifyChanged();
            return false;
        }

        RefreshCore();
        NotifyChanged();
        if (mode != "learning" && new ConfirmModeWindow { Owner = owner }.ShowDialog() != true)
        {
            Call(new ApiRequest { Op = ApiOps.SetMode, Mode = previous });
            Message?.Invoke(this, $"Switched back to {previous} mode.");
            RefreshCore();
            NotifyChanged();
            return false;
        }

        Message?.Invoke(this, $"{ModeName(mode)} mode is on.");
        OfferAutostart(owner, mode);
        return true;
    }

    /// <summary>Ask mode only works while the app runs: offer once to start it with Windows.</summary>
    private void OfferAutostart(Window owner, string mode)
    {
        if (mode != "ask" || Prefs.Current.AutostartAsked || Autostart.IsEnabled)
        {
            return;
        }

        Prefs.Current.AutostartAsked = true;
        Prefs.Save();
        var choice = ChoiceDialog.Ask(
            owner,
            "Start CrioFire with Windows?",
            "In Ask mode CrioFire asks you about each new program, but it can only ask while the app is running. Start it quietly in the notification area when you sign in?",
            ["Start with Windows", "Not now"],
            defaultIndex: 0);
        if (choice == 0)
        {
            Message?.Invoke(this, Autostart.Set(true)
                ? "CrioFire will start when you sign in to Windows."
                : "Could not change the Windows startup setting.");
        }
    }

    public void Panic(Window owner)
    {
        var choice = ChoiceDialog.Ask(
            owner,
            "Remove every CrioFire rule?",
            "This removes all your allow and block rules and switches back to Learning mode. Use it if something can't connect and you don't know why.",
            ["Remove everything", "Cancel"],
            defaultIndex: 1,
            danger: true);
        if (choice == 0 && Call(new ApiRequest { Op = ApiOps.Panic }) is { } result)
        {
            Pending.Clear();
            Message?.Invoke(this, $"Removed {result.Count} filters. CrioFire is back in Learning mode.");
            NotifyChanged();
        }
    }

    public void AddPending(EventInfo blocked) => Pending.Add(new PendingAlert(blocked));

    public void Resolve(string app)
    {
        foreach (var p in Pending.Where(p => string.Equals(p.App, app, StringComparison.OrdinalIgnoreCase)).ToList())
        {
            Pending.Remove(p);
        }

        PendingResolved?.Invoke(this, app);
    }

    public void GoTo(string page) => NavigateRequested?.Invoke(this, page);

    /// <summary>Opens the Activity page on its list of allowed connections.</summary>
    public void ShowAllowed()
    {
        _showAllowed = true;
        GoTo("Activity");
    }

    /// <summary>True once after <see cref="ShowAllowed"/>: the Activity page switches to its allowed list.</summary>
    public bool TakeShowAllowed()
    {
        var value = _showAllowed;
        _showAllowed = false;
        return value;
    }

    public void NotifyChanged() => Changed?.Invoke(this, EventArgs.Empty);

    public void Say(string? message) => Message?.Invoke(this, message);

    public static string ModeName(string mode) => mode switch
    {
        "ask" => "Ask",
        "allowlist" => "Allow-list",
        _ => "Learning",
    };

    private static List<string> RunningPrograms()
    {
        var paths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var process in System.Diagnostics.Process.GetProcesses())
        {
            using (process)
            {
                try
                {
                    if (process.MainModule?.FileName is { Length: > 0 } path)
                    {
                        paths.Add(path);
                    }
                }
                catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException or NotSupportedException)
                {
                }
            }
        }

        return [.. paths];
    }
}

/// <summary>Arc geometry for the protection ring and the direction donut.</summary>
internal static class Arcs
{
    public static Geometry Arc(double fraction, double center, double radius)
    {
        fraction = Math.Clamp(fraction, 0, 0.9999);
        var angle = fraction * 2 * Math.PI;
        var start = new Point(center, center - radius);
        var end = new Point(center + (radius * Math.Sin(angle)), center - (radius * Math.Cos(angle)));
        var figure = new PathFigure { StartPoint = start, IsClosed = false, IsFilled = false };
        figure.Segments.Add(new ArcSegment(end, new Size(radius, radius), 0, fraction > 0.5, SweepDirection.Clockwise, isStroked: true));
        var geometry = new PathGeometry();
        geometry.Figures.Add(figure);
        geometry.Freeze();
        return geometry;
    }
}

internal static class Fmt
{
    public static string Count(int n) => n.ToString("N0", CultureInfo.CurrentCulture);

    public static string Time(DateTime utc) => utc.ToLocalTime().ToString("HH:mm", CultureInfo.CurrentCulture);

    public static string Ago(DateTime utc)
    {
        var span = DateTime.UtcNow - utc;
        return span.TotalMinutes < 1 ? "just now"
            : span.TotalHours < 1 ? $"{(int)span.TotalMinutes} min ago"
            : span.TotalDays < 1 ? $"{(int)span.TotalHours} h ago"
            : utc.ToLocalTime().ToString("ddd d MMM", CultureInfo.CurrentCulture);
    }
}
