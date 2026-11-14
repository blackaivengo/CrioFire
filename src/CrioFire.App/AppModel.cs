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
            if (!response.Ok && response.Code == ApiOps.ApprovalRequired)
            {
                return Elevated.Call(request, out error);   // tamper protection: ask Windows for approval
            }

            error = response.Ok ? null : Explain(request.Op, response.Error);
            return response.Ok ? response : null;
        }
        catch (IOException ex)
        {
            error = $"Lost the connection to the CrioFire service: {ex.Message}";
            return null;
        }
    }

    /// <summary>An older service does not know the newer operations; say so plainly.</summary>
    private static string? Explain(string? op, string? error) =>
        error is not null && error.StartsWith("Unknown operation", StringComparison.Ordinal)
            ? $"The CrioFire service on this PC is older than this app and can't answer '{op}' yet. Install the latest CrioFire (it updates the service too), then open this view again."
            : error;
}

/// <summary>
/// Tamper protection is on, so a change needs administrator approval: runs CrioFire's own
/// command line elevated (Windows shows its approval prompt) with the one request on its command
/// line, and reads the answer it writes back.
/// </summary>
internal static class Elevated
{
    /// <summary>Command lines are limited to 32,767 characters; larger requests (big imports) need an administrator prompt.</summary>
    private const int MaxArgument = 30_000;

    public static ApiResponse? Call(ApiRequest request, out string? error)
    {
        var cli = Path.Combine(AppContext.BaseDirectory, "criofire.exe");
        if (!File.Exists(cli))
        {
            error = "Tamper protection is on, and CrioFire's command line was not found next to the app to ask for approval.";
            return null;
        }

        var argument = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(ApiJson.Serialize(request)));
        if (argument.Length > MaxArgument)
        {
            error = "Tamper protection is on and this change is too large to approve from the app. Use 'criofire import' from an administrator prompt.";
            return null;
        }

        var result = Path.Combine(Path.GetTempPath(), $"criofire-approval-{Guid.NewGuid():N}.json");
        try
        {
            var start = new System.Diagnostics.ProcessStartInfo(cli, $"request {argument} \"{result}\"")
            {
                UseShellExecute = true,
                Verb = "runas",
                WindowStyle = System.Diagnostics.ProcessWindowStyle.Hidden,
            };
            using var process = System.Diagnostics.Process.Start(start);
            if (process is null || !process.WaitForExit(TimeSpan.FromMinutes(2)) || !File.Exists(result))
            {
                error = "The change was not made: approval did not finish.";
                return null;
            }

            var response = ApiJson.DeserializeResponse(File.ReadAllText(result));
            error = response is { Ok: true } ? null : response?.Error ?? "The change failed.";
            return response is { Ok: true } ? response : null;
        }
        catch (System.ComponentModel.Win32Exception ex) when (ex.NativeErrorCode == 1223)
        {
            error = "The change was not made: it was not approved.";
            return null;
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or IOException or System.Text.Json.JsonException)
        {
            error = $"The change was not made: {ex.Message}";
            return null;
        }
        finally
        {
            try
            {
                File.Delete(result);
            }
            catch (IOException)
            {
            }
        }
    }
}

/// <summary>A program the Ask mode stopped, waiting for the user's decision.</summary>
/// <summary>What the Activity page should show when a panel opens it.</summary>
/// <param name="Kind">blocked, allowed or all.</param>
/// <param name="Minutes">The time window: 60, 1440, 10080 or 43200.</param>
/// <param name="Why">A reason group (mine, norule, automatic, loopback, panic), or null for all.</param>
/// <param name="Sort">recent or count.</param>
internal sealed record ActivityQuery(string Kind = "blocked", int Minutes = 1440, string? Why = null, string? App = null, string? Service = null, string? Search = null, string? Sort = null);

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
    private ActivityQuery? _activityQuery;

    public StatusInfo? Status { get; private set; }

    public IReadOnlyList<RuleInfo> Rules { get; private set; } = [];

    /// <summary>CrioFire's automatic permits (Windows services, Windows kernel) and whether they are on.</summary>
    public IReadOnlyList<AutoRuleInfo> AutoRules { get; private set; } = [];

    /// <summary>The domain rules, with how many addresses each covers now.</summary>
    public IReadOnlyList<DomainRuleInfo> DomainRules { get; private set; } = [];

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
        .GroupBy(r => (r.App?.ToUpperInvariant(), r.Action, r.Direction, r.Managed))
        .Select(g => g.First());

    /// <summary>Network rules (port/address), one entry per rule rather than per filter.</summary>
    public IEnumerable<RuleInfo> NetRules => Rules
        .Where(r => r.Kind == nameof(FilterKind.NetRule))
        .GroupBy(r => (r.Action, r.Direction, r.Protocol, r.Ports, r.Addresses, r.App?.ToUpperInvariant(), r.Managed))
        .Select(g => g.First());

    /// <summary>Service rules, one entry per service/action/direction.</summary>
    public IEnumerable<RuleInfo> ServiceRules => Rules
        .Where(r => r.Kind == nameof(FilterKind.ServiceRule))
        .GroupBy(r => (r.Service?.ToUpperInvariant(), r.Action, r.Direction, r.Managed))
        .Select(g => g.First());

    public bool SetServiceRule(string service, string action, string direction = "out", NetworkProfiles networks = NetworkProfiles.Any)
    {
        var ok = Call(new ApiRequest { Op = ApiOps.SetServiceRule, Service = service, Action = action, Direction = direction, Networks = NetworkScope.TextOrNull(networks) }) is not null;
        if (ok)
        {
            var where = NetworkScope.Normalize(networks) == NetworkProfiles.Any ? string.Empty : $" on {NetworkScope.Label(networks)}";
            Message?.Invoke(this, action == "allow" ? $"Allowed the service {service}{where}." : $"Blocked the service {service}{where}.");
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
                ? "Windows services such as DNS (name lookups), DHCP and Windows Update will need their own rules. Until you add them, programs without a rule may not reach anything by name.\n\nTip: block or allow single services under Rules instead."
                : "Kernel traffic such as file and printer sharing (SMB) and NetBIOS will need its own rule.";
            var choice = ChoiceDialog.Ask(owner, $"Stop allowing {what} automatically?", warning + "\n\nThis applies in Ask and Allow-list modes.",
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

    public static string AutoRuleName(string name) => name switch
    {
        AutoRulePolicy.WindowsKernel => "Windows kernel connections",
        AutoRulePolicy.LocalNetwork => "Local network connections",
        _ => "Windows services",
    };

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
            return ServiceRuleDialog.Ask(owner, null, action) is { } picked && SetServiceRule(picked.Service, picked.Action, picked.Direction, picked.Networks);
        }

        if (action == "block" && ChoiceDialog.Ask(owner, "Block every Windows service?",
                "DNS, DHCP, Windows Update and dozens of other services will lose network access, and programs will no longer find anything by name. Undo it under Rules.",
                ["Block svchost.exe", "Cancel"], defaultIndex: 1, danger: true) != 0)
        {
            return false;
        }

        return SetRule(app, action);
    }

    public bool SetDomainRule(string domain, string action, string? app, NetworkProfiles networks)
    {
        var ok = Call(new ApiRequest { Op = ApiOps.SetDomainRule, Domain = domain, Action = action, App = app, Networks = NetworkScope.TextOrNull(networks) }) is not null;
        if (ok)
        {
            Message?.Invoke(this, $"{(action == "allow" ? "Allowing" : "Blocking")} {domain} and every name under it. The addresses follow name lookups and apply within a few seconds.");
            NotifyChanged();
        }

        return ok;
    }

    public bool RemoveDomainRule(DomainRuleInfo rule)
    {
        ArgumentNullException.ThrowIfNull(rule);
        var ok = Call(new ApiRequest { Op = ApiOps.RemoveDomainRule, DomainRuleId = rule.Id }) is not null;
        if (ok)
        {
            Message?.Invoke(this, $"Removed the rule for {rule.Domain}.");
            NotifyChanged();
        }

        return ok;
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
            Networks = NetworkScope.TextOrNull(rule.Networks),
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

    public bool RefreshCore() => ApplyCore(ReadCore());

    /// <summary>
    /// The same as <see cref="RefreshCore"/>, but the service calls run off the UI thread, so the
    /// window keeps responding (and can show progress) while the service answers.
    /// </summary>
    public async Task<bool> RefreshCoreAsync() => ApplyCore(await Task.Run(ReadCore));

    private sealed record CoreState(StatusInfo? Status, ApiResponse? List, string? Error, List<DomainRuleInfo>? Domains = null);

    private static CoreState ReadCore()
    {
        var status = Service.Call(new ApiRequest { Op = ApiOps.Status }, out var error);
        ApiResponse? list = null;
        List<DomainRuleInfo>? domains = null;
        if (status is not null)
        {
            list = Service.Call(new ApiRequest { Op = ApiOps.List }, out error);
            domains = Service.Call(new ApiRequest { Op = ApiOps.Domains }, out _)?.Domains;   // an older service has none
        }

        return new CoreState(status?.Status, list, error, domains);
    }

    private bool ApplyCore(CoreState state)
    {
        Status = state.Status;
        if (state.Status is not null)
        {
            Rules = state.List?.Rules ?? [];
            AutoRules = state.List?.AutoRules ?? [];
            DomainRules = state.Domains ?? [];
        }

        Error = state.Error;
        return state.Status is not null;
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

    /// <summary>
    /// Switches rules between allow and block, and/or to another direction, keeping everything else
    /// (program, ports, addresses, service). <paramref name="action"/> and <paramref name="direction"/>
    /// left null keep each rule's own.
    /// </summary>
    /// <param name="networks">The kinds of network the rules should apply on ("any", "public", "domain,private"), or null to keep them.</param>
    public void ChangeRules(IReadOnlyList<RuleInfo> rules, string? action, string? direction, string? networks = null)
    {
        if (OrganizationOnly(ref rules))
        {
            return;
        }

        int changed = 0, failed = 0;
        foreach (var r in rules)
        {
            var newAction = action ?? r.Action ?? "block";
            var newDirection = direction ?? r.Direction ?? "out";
            var newNetworks = networks is null ? r.Networks : NetworkScope.TryParse(networks, out var n) ? NetworkScope.TextOrNull(n) : r.Networks;
            if (newAction == r.Action && newDirection == r.Direction && newNetworks == r.Networks)
            {
                continue;
            }

            var ok = r.Kind switch
            {
                nameof(FilterKind.AppRule) when r.App is not null =>
                    (newDirection == r.Direction || Call(new ApiRequest { Op = ApiOps.RemoveRules, App = r.App, Direction = r.Direction }) is not null)
                    && Call(new ApiRequest { Op = ApiOps.SetRule, App = r.App, Action = newAction, Direction = newDirection, Networks = newNetworks }) is not null,
                nameof(FilterKind.ServiceRule) when r.Service is not null =>
                    (newDirection == r.Direction || Call(new ApiRequest { Op = ApiOps.RemoveServiceRules, Service = r.Service, Direction = r.Direction }) is not null)
                    && Call(new ApiRequest { Op = ApiOps.SetServiceRule, Service = r.Service, Action = newAction, Direction = newDirection, Networks = newNetworks }) is not null,
                nameof(FilterKind.NetRule) => ReplaceNetRule(r, newAction, newDirection, newNetworks ?? "any"),
                _ => false,
            };
            if (ok)
            {
                changed++;
            }
            else
            {
                failed++;
            }
        }

        var what = networks is not null ? $"to {NetworkScope.Label(NetworkScope.TryParse(networks, out var label) ? label : NetworkProfiles.Any)}"
            : action is null ? $"to {(direction == "in" ? "inbound" : direction == "both" ? "both directions" : "outbound")}" : $"to {action}";
        Message?.Invoke(this, changed == 0 && failed == 0
            ? "Nothing to change."
            : $"Switched {changed} rule{(changed == 1 ? string.Empty : "s")} {what}." + (failed > 0 ? $" {failed} could not be changed." : string.Empty));
        RefreshCore();
        NotifyChanged();
    }

    /// <summary>Adds the changed network rule first, then removes the old one, so there is no moment without a rule.</summary>
    private bool ReplaceNetRule(RuleInfo r, string action, string direction, string networks)
    {
        if (RuleViews.Changed(r, action, direction, networks) is not { } rule)
        {
            return false;
        }

        var added = Call(new ApiRequest
        {
            Op = ApiOps.AddNetRule,
            Action = action,
            Direction = direction,
            Protocol = NetRule.ProtocolText(rule.Protocol),
            Ports = rule.Ports.Length == 0 ? null : rule.Ports,
            Addresses = rule.Addresses.Length == 0 ? null : rule.Addresses,
            App = rule.AppPath,
            Networks = NetworkScope.TextOrNull(rule.Networks),
        }) is not null;
        return added && Call(new ApiRequest { Op = ApiOps.RemoveFilter, FilterId = r.FilterId }) is not null;
    }

    /// <summary>Removes rules of every kind at once.</summary>
    public void RemoveMany(IReadOnlyList<RuleInfo> rules)
    {
        if (OrganizationOnly(ref rules))
        {
            return;
        }

        var removed = 0;
        foreach (var r in rules)
        {
            var ok = r.Kind switch
            {
                nameof(FilterKind.AppRule) when r.App is not null => Call(new ApiRequest { Op = ApiOps.RemoveRules, App = r.App, Direction = r.Direction }) is not null,
                nameof(FilterKind.ServiceRule) when r.Service is not null => Call(new ApiRequest { Op = ApiOps.RemoveServiceRules, Service = r.Service, Direction = r.Direction }) is not null,
                nameof(FilterKind.NetRule) => Call(new ApiRequest { Op = ApiOps.RemoveFilter, FilterId = r.FilterId }) is not null,
                _ => false,
            };
            removed += ok ? 1 : 0;
        }

        Message?.Invoke(this, $"Removed {removed} rule{(removed == 1 ? string.Empty : "s")}.");
        RefreshCore();
        NotifyChanged();
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

    /// <summary>The panic switch: off, allow (everything allowed, rules paused) or block (all network traffic blocked).</summary>
    public string PanicMode => Status?.Panic ?? "off";

    /// <summary>Offers the panic choices; removing every rule is confirmed a second time.</summary>
    public void ShowPanic(Window owner)
    {
        var action = PanicDialog.Ask(owner, PanicMode);
        if (action is null)
        {
            return;
        }

        if (action == "remove")
        {
            var count = Rules.Count(r => r.Kind is nameof(FilterKind.AppRule) or nameof(FilterKind.NetRule) or nameof(FilterKind.ServiceRule));
            var confirm = ChoiceDialog.Ask(
                owner,
                "Delete every rule?",
                $"This deletes all {count} filters of your program, network and service rules and switches to Learning mode. It cannot be undone.\n\n'Allow everything, pause my rules' gets you connected too, and keeps them.",
                ["Delete every rule", "Pause them instead", "Cancel"],
                defaultIndex: 2,
                danger: true);
            action = confirm switch { 0 => "remove", 1 => "allow", _ => null };
            if (action is null)
            {
                return;
            }
        }

        SetPanic(action);
    }

    /// <summary>The company CrioFire Server this PC reports to, or null.</summary>
    public static CrioFire.Core.Management.ManagementInfo? Management() =>
        Service.Call(new ApiRequest { Op = ApiOps.Management }, out _)?.Management;

    /// <summary>The license on this PC, or null when the service cannot answer.</summary>
    public static LicenseStatus? License() => Service.Call(new ApiRequest { Op = ApiOps.License }, out _)?.License;

    /// <summary>Enters (or, with an empty key, removes) the license key; returns the new status, or null with a message.</summary>
    public LicenseStatus? SetLicense(string key)
    {
        var status = Call(new ApiRequest { Op = ApiOps.SetLicense, LicenseKey = key })?.License;
        if (status is not null)
        {
            Message?.Invoke(this, status.Message);
        }

        return status;
    }

    /// <summary>Turns tamper protection on or off (Windows asks for administrator approval).</summary>
    public bool SetProtection(bool on)
    {
        var ok = Call(new ApiRequest { Op = ApiOps.SetProtection, Enabled = on }) is not null;
        if (ok)
        {
            Message?.Invoke(this, on
                ? "Tamper protection is on: rule changes ask for administrator approval."
                : "Tamper protection is off.");
            RefreshCore();
            NotifyChanged();
        }

        return ok;
    }

    /// <summary>Every rule in force, for saving to a file; null (with a message) when the service cannot answer.</summary>
    public RuleSet? ExportRules() => Call(new ApiRequest { Op = ApiOps.ExportRules })?.RuleSet;

    /// <summary>What importing a rules file would do, without changing anything.</summary>
    public ImportPlan? PlanImport(RuleSet set, string importMode) =>
        Call(new ApiRequest { Op = ApiOps.ImportRules, RuleSet = set, ImportMode = importMode, DryRun = true })?.Plan;

    /// <summary>Imports a rules file (merge or replace). A backup of the current rules is saved first.</summary>
    public bool ImportRules(RuleSet set, string importMode)
    {
        var plan = Call(new ApiRequest { Op = ApiOps.ImportRules, RuleSet = set, ImportMode = importMode })?.Plan;
        if (plan is null)
        {
            return false;
        }

        Message?.Invoke(this, $"Imported: {plan.Add} added, {plan.Change} changed, {plan.Remove} removed"
            + (plan.Missing.Count > 0 ? $", {plan.Missing.Count} skipped (program not on this PC)." : "."));
        RefreshCore();
        NotifyChanged();
        return true;
    }

    /// <summary>The saved rule backups, newest first.</summary>
    /// <summary>
    /// Leaves out rules set by the organization (they cannot be changed on this PC). Returns true,
    /// after saying so, when nothing is left to change.
    /// </summary>
    private bool OrganizationOnly(ref IReadOnlyList<RuleInfo> rules)
    {
        var own = rules.Where(r => !r.Managed).ToList();
        if (own.Count < rules.Count)
        {
            Message?.Invoke(this, own.Count == 0
                ? "Rules set by your organization cannot be changed on this PC."
                : "Rules set by your organization were left as they are.");
        }

        rules = own;
        return own.Count == 0;
    }

    /// <summary>The update check's setting and last result; null when the service is not running (or too old).</summary>
    public static UpdateState? UpdateState() => Service.Call(new ApiRequest { Op = ApiOps.Update }, out _)?.Update;

    /// <summary>Asks GitHub now, through the service (whose connections are always allowed). Any thread: raises no events.</summary>
    public static (UpdateState? State, string? Error) CheckUpdate()
    {
        var state = Service.Call(new ApiRequest { Op = ApiOps.CheckUpdate }, out var error)?.Update;
        return (state, state is null ? error : null);
    }

    public bool SetUpdateCheck(bool enabled)
    {
        var ok = Call(new ApiRequest { Op = ApiOps.SetUpdateCheck, Enabled = enabled }) is not null;
        if (ok)
        {
            Message?.Invoke(this, enabled ? "CrioFire will look for a newer version once a day." : "CrioFire will not look for newer versions.");
        }

        return ok;
    }

    /// <summary>The history settings and sizes; null when the service is not running (or too old).</summary>
    public static LogsInfo? Logs() => Service.Call(new ApiRequest { Op = ApiOps.Logs }, out _)?.Logs;

    public bool SetLogs(LogSettings settings)
    {
        var ok = Call(new ApiRequest { Op = ApiOps.SetLogs, LogSettings = settings }) is not null;
        if (ok)
        {
            Message?.Invoke(this, "History settings saved; they apply within a minute.");
        }

        return ok;
    }

    public bool ClearLogs()
    {
        var ok = Call(new ApiRequest { Op = ApiOps.ClearLogs }) is not null;
        if (ok)
        {
            Message?.Invoke(this, "Connection history cleared.");
            NotifyChanged();
        }

        return ok;
    }

    public static IReadOnlyList<BackupInfo> Backups() =>
        Service.Call(new ApiRequest { Op = ApiOps.Backups }, out _)?.Backups ?? [];

    public ImportPlan? PlanRestore(string name) =>
        Call(new ApiRequest { Op = ApiOps.RestoreBackup, Name = name, DryRun = true })?.Plan;

    /// <summary>Puts the rules back exactly as in a backup (the current ones are backed up first).</summary>
    public bool RestoreBackup(string name)
    {
        var plan = Call(new ApiRequest { Op = ApiOps.RestoreBackup, Name = name })?.Plan;
        if (plan is null)
        {
            return false;
        }

        Message?.Invoke(this, $"Restored the backup: {plan.Add} added, {plan.Change} changed, {plan.Remove} removed.");
        RefreshCore();
        NotifyChanged();
        return true;
    }

    /// <summary>Allowed programs whose file changed since they were allowed.</summary>
    public static IReadOnlyList<ChangedProgram> ChangedPrograms() =>
        Service.Call(new ApiRequest { Op = ApiOps.Changed }, out _)?.Changed ?? [];

    /// <summary>The user checked the changed program: allow it again as it is now.</summary>
    public bool TrustChanged(ChangedProgram program)
    {
        ArgumentNullException.ThrowIfNull(program);
        var ok = Call(new ApiRequest { Op = ApiOps.Trust, App = program.App, Direction = program.Direction }) is not null;
        if (ok)
        {
            Message?.Invoke(this, $"Allowed {KnownApps.DisplayName(program.App)} again as it is now.");
            RefreshCore();
            NotifyChanged();
        }

        return ok;
    }

    /// <summary>The user does not trust the changed program: block it (in the direction it was allowed).</summary>
    public bool BlockChanged(ChangedProgram program)
    {
        ArgumentNullException.ThrowIfNull(program);
        var ok = Call(new ApiRequest { Op = ApiOps.SetRule, App = program.App, Action = "block", Direction = program.Direction }) is not null;
        if (ok)
        {
            Resolve(program.App);
            Message?.Invoke(this, $"Blocked {KnownApps.DisplayName(program.App)}.");
            RefreshCore();
            NotifyChanged();
        }

        return ok;
    }

    /// <summary>Ends panic: rules and mode apply again.</summary>
    public void Resume() => SetPanic("off");

    /// <summary>Allow everything (rules paused) or block all traffic; never removes rules.</summary>
    public void Panic(string action)
    {
        if (action is "allow" or "block")
        {
            SetPanic(action);
        }
    }

    private void SetPanic(string action)
    {
        if (Call(new ApiRequest { Op = ApiOps.Panic, Action = action }) is not { } result)
        {
            return;
        }

        if (action is "remove" or "block")
        {
            Pending.Clear();
        }

        Message?.Invoke(this, action switch
        {
            "remove" => $"Removed {result.Count} filters. Every rule is gone and CrioFire is in Learning mode.",
            "block" => "Panic: all network traffic is blocked. Your rules are kept; Resume brings them back.",
            "allow" => "Panic: everything is allowed and your rules are paused. Resume brings them back.",
            _ => "Panic is off. Your rules apply again.",
        });
        RefreshCore();
        NotifyChanged();
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

    /// <summary>Opens the Activity page with a filter, e.g. from a dashboard panel.</summary>
    public void OpenActivity(ActivityQuery query)
    {
        _activityQuery = query;
        GoTo("Activity");
    }

    /// <summary>Opens the Activity page on its list of allowed connections.</summary>
    public void ShowAllowed() => OpenActivity(new ActivityQuery("allowed"));

    /// <summary>The filter a panel asked for, once: the Activity page applies it.</summary>
    public ActivityQuery? TakeActivityQuery()
    {
        var value = _activityQuery;
        _activityQuery = null;
        return value;
    }

    /// <summary>
    /// Allows (optionally for a while) or blocks what made the selected connections, in one go: a
    /// rule per program and direction, a service rule for a known service in svchost.exe, and for
    /// blocked traffic stopped by a port/address rule, that rule is removed. Confirmed when it
    /// affects more than one thing; svchost.exe connections whose service is unknown are skipped.
    /// </summary>
    public void ApplyToMany(Window owner, IReadOnlyList<TrafficItem> items, string action, int? minutes = null)
    {
        if (items.Count == 0)
        {
            Say("Select one or more rows first (Ctrl or Shift to select several).");
            return;
        }

        if (items.Count == 1 && KnownApps.IsServiceHost(items[0].App)
            && (items[0].Service ?? string.Empty).Split(',', StringSplitOptions.RemoveEmptyEntries).Length != 1
            && !(action == "allow" && items[0] is { Allowed: false, Why: nameof(FilterKind.NetRule) or nameof(FilterKind.ServiceRule) }))
        {
            Decide(owner, items[0].App, items[0].Service, action);   // asks which service
            return;
        }

        var apps = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);
        var services = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);
        var netRules = new HashSet<ulong>();
        int panic = 0, unknownService = 0, unknown = 0;
        foreach (var item in items)
        {
            var direction = item.Direction == "in" ? "in" : "out";
            if (!item.Allowed && item.Why == nameof(FilterKind.Panic))
            {
                panic++;
                continue;
            }

            if (action == "allow" && !item.Allowed && item.Why == nameof(FilterKind.NetRule) && item.FilterId != 0)
            {
                netRules.Add(item.FilterId);
                continue;
            }

            if (action == "allow" && !item.Allowed && item.Why == nameof(FilterKind.ServiceRule))
            {
                if (Rules.FirstOrDefault(r => r.FilterId == item.FilterId)?.Service is { } blockedService)
                {
                    Add(services, blockedService, direction);
                }
                else
                {
                    unknown++;
                }

                continue;
            }

            if (string.IsNullOrEmpty(item.App))
            {
                unknown++;
                continue;
            }

            if (KnownApps.IsServiceHost(item.App))
            {
                var names = (item.Service ?? string.Empty).Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                if (names.Length == 1)
                {
                    Add(services, names[0], direction);
                }
                else
                {
                    unknownService++;
                }

                continue;
            }

            Add(apps, item.App, direction);
        }

        var verb = action == "allow" ? (minutes is int m ? $"Allow for {m} minutes" : "Allow") : "Block";
        var notes = new List<string>();
        if (panic > 0)
        {
            notes.Add($"{panic} rows were blocked by panic: resume your rules instead.");
        }

        if (unknownService > 0)
        {
            notes.Add($"{unknownService} rows came from svchost.exe without a known service; open one on its own to pick the service.");
        }

        if (unknown > 0)
        {
            notes.Add($"{unknown} rows have no program CrioFire can make a rule for.");
        }

        var count = apps.Count + services.Count + netRules.Count;
        if (count == 0)
        {
            Say(notes.Count > 0 ? string.Join(" ", notes) : "Nothing to change.");
            return;
        }

        if (count > 1 || netRules.Count > 0)
        {
            var names = apps.Keys.Select(KnownApps.DisplayName).Concat(services.Keys.Select(s => $"service {s}")).ToList();
            var text = names.Count == 0 ? string.Empty
                : string.Join(", ", names.Take(8)) + (names.Count > 8 ? $" and {names.Count - 8} more" : string.Empty) + ".";
            if (netRules.Count > 0)
            {
                text += $"{(text.Length > 0 ? "\n\n" : string.Empty)}Also remove {netRules.Count} port/address rule{(netRules.Count == 1 ? string.Empty : "s")} that blocked them. They may cover other programs too.";
            }

            if (minutes is not null && services.Count > 0)
            {
                text += "\n\nService rules have no time limit: services are allowed until you change it.";
            }

            if (notes.Count > 0)
            {
                text += "\n\n" + string.Join("\n", notes);
            }

            var title = $"{verb}: {apps.Count + services.Count} program{(apps.Count + services.Count == 1 ? string.Empty : "s")} and services";
            if (ChoiceDialog.Ask(owner, title, text, [verb, "Cancel"], defaultIndex: 0, danger: action == "block") != 0)
            {
                return;
            }
        }

        var done = 0;
        foreach (var (app, directions) in apps)
        {
            if (Call(new ApiRequest { Op = ApiOps.SetRule, App = app, Action = action, Direction = Both(directions), ExpiresMinutes = action == "allow" ? minutes : null }) is not null)
            {
                done++;
                if (action == "allow")
                {
                    Resolve(app);
                }
            }
        }

        foreach (var (service, directions) in services)
        {
            done += Call(new ApiRequest { Op = ApiOps.SetServiceRule, Service = service, Action = action, Direction = Both(directions) }) is not null ? 1 : 0;
        }

        foreach (var id in netRules)
        {
            done += Call(new ApiRequest { Op = ApiOps.RemoveFilter, FilterId = id }) is not null ? 1 : 0;
        }

        Message?.Invoke(this, $"{(action == "allow" ? "Allowed" : "Blocked")}: {done} of {count} done." + (notes.Count > 0 ? " " + string.Join(" ", notes) : string.Empty));
        RefreshCore();
        NotifyChanged();

        static void Add(Dictionary<string, HashSet<string>> map, string key, string direction)
        {
            if (!map.TryGetValue(key, out var set))
            {
                set = [];
                map[key] = set;
            }

            set.Add(direction);
        }

        static string Both(HashSet<string> directions) => directions.Count > 1 ? "both" : directions.First();
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
