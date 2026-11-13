using System.ComponentModel;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Media;
using CrioFire.Core;
using CrioFire.Core.Api;
using Microsoft.Win32;

namespace CrioFire.App.Pages;

/// <summary>
/// The user's rules: what is blocked at a glance (ports, addresses), filters and sorting, a click to
/// switch a rule between allow and block, several rules switched or removed at once, and the
/// automatic rules.
/// </summary>
public partial class RulesPage : UserControl, IPage
{
    private readonly AppModel _model;
    private readonly Dictionary<ListView, (string Property, ListSortDirection Direction)> _sort = [];

    internal RulesPage(AppModel model)
    {
        _model = model;
        InitializeComponent();
        foreach (var list in Lists)
        {
            list.AddHandler(GridViewColumnHeader.ClickEvent, new RoutedEventHandler(OnHeaderClick));
            var menu = new ContextMenu();
            list.ContextMenu = menu;
            list.ContextMenuOpening += (_, e) => OnMenuOpening(menu, e);
        }
    }

    public string Title => "Rules";

    public string Subtitle { get; private set; } = string.Empty;

    /// <summary>Export and Import, in the page header.</summary>
    public FrameworkElement? Actions => _actions ??= BuildActions();

    private StackPanel? _actions;

    public TimeSpan? AutoRefresh => null;

    private ListView[] Lists => [Table, NetTable, ServiceTable];

    private string? ActionFilter => ActionAllow.IsChecked == true ? "allow" : ActionBlock.IsChecked == true ? "block" : null;

    private string? DirectionFilter => DirOut.IsChecked == true ? "out" : DirIn.IsChecked == true ? "in" : null;

    public void Refresh()
    {
        var chipFire = (Brush)FindResource("ChipFireBrush");
        var chipFireText = (Brush)FindResource("ChipFireTextBrush");
        var chipIce = (Brush)FindResource("ChipIceBrush");
        var chipIceText = (Brush)FindResource("ChipIceTextBrush");
        var search = SearchBox.Text.Trim();
        bool Show(RuleInfo r) => RuleViews.Matches(r, search, ActionFilter, DirectionFilter);

        var allPrograms = _model.AppRules.ToList();
        var rows = allPrograms.Where(Show)
            .OrderBy(r => r.Action)
            .ThenBy(r => KnownApps.DisplayName(r.App), StringComparer.OrdinalIgnoreCase)
            .Select(r =>
            {
                var allow = r.Action == "allow";
                return new RuleRow(
                    r,
                    allow ? "Allow" : "Block",
                    Who.Direction(r.Direction) + Networks(r),
                    KnownApps.DisplayName(r.App) + Organization(r),
                    r.App ?? r.Name,
                    r.ExpiresUtc is DateTime t ? Fmt.Time(t) : "always",
                    allow ? chipIce : chipFire,
                    allow ? chipIceText : chipFireText);
            })
            .ToList();
        Table.ItemsSource = rows;
        Empty.Visibility = rows.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        Empty.Text = allPrograms.Count == 0
            ? "No rules yet. Allow or block a program above, or answer an alert in Ask mode."
            : "No program rule matches the filters.";
        ProgramsTitle.Text = Count("Programs", rows.Count, allPrograms.Count);

        var allNet = _model.NetRules.ToList();
        var netRows = allNet.Where(Show)
            .OrderBy(r => r.Action)
            .ThenBy(r => r.Summary, StringComparer.OrdinalIgnoreCase)
            .Select(r =>
            {
                var allow = r.Action == "allow";
                var rule = string.Join(" · ", new[]
                {
                    r.Protocol is null or "any" ? null : r.Protocol.ToUpperInvariant(),
                    r.Ports is null ? null : (r.Direction == "in" ? "local port " : "port ") + r.Ports + PortNames(r.Ports),
                    r.Addresses,
                }.Where(p => p is not null));
                return new NetRuleRow(
                    r,
                    allow ? "Allow" : "Block",
                    Who.Direction(r.Direction) + Networks(r),
                    rule,
                    (r.App is null ? "Any program" : KnownApps.DisplayName(r.App)) + Organization(r),
                    r.App,
                    r.FilterId,
                    allow ? chipIce : chipFire,
                    allow ? chipIceText : chipFireText);
            })
            .ToList();
        NetTable.ItemsSource = netRows;
        NetEmpty.Visibility = netRows.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        NetEmpty.Text = allNet.Count == 0
            ? "No network rules. Add one to block a port like 445 inbound, keep a program to port 443, or block an address range."
            : "No port or address rule matches the filters.";
        NetTitle.Text = Count("Ports and addresses", netRows.Count, allNet.Count);

        var displayNames = _displayNames ?? ServiceDisplayNames();
        _displayNames = null;
        var allServices = _model.ServiceRules.ToList();
        var serviceRows = allServices.Where(r => Show(r) || (r.Service is not null && displayNames.TryGetValue(r.Service, out var d)
                && search.Length > 0 && RuleViews.Matches(r with { Name = d }, search, ActionFilter, DirectionFilter)))
            .OrderBy(r => r.Action)
            .ThenBy(r => r.Service, StringComparer.OrdinalIgnoreCase)
            .Select(r =>
            {
                var allow = r.Action == "allow";
                var service = r.Service ?? "?";
                return new ServiceRuleRow(
                    r,
                    allow ? "Allow" : "Block",
                    Who.Direction(r.Direction) + Networks(r),
                    service,
                    (displayNames.TryGetValue(service, out var display) ? display : service) + Organization(r),
                    allow ? chipIce : chipFire,
                    allow ? chipIceText : chipFireText);
            })
            .ToList();
        ServiceTable.ItemsSource = serviceRows;
        ServiceEmpty.Visibility = serviceRows.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        ServiceEmpty.Text = allServices.Count == 0
            ? "No service rules. Block or allow one with 'Service rule...', or from Activity."
            : "No service rule matches the filters.";
        ServiceTitle.Text = Count("Windows services", serviceRows.Count, allServices.Count);

        ProgramsCard.Visibility = ShowNet.IsChecked == true || ShowServices.IsChecked == true ? Visibility.Collapsed : Visibility.Visible;
        NetCard.Visibility = ShowPrograms.IsChecked == true || ShowServices.IsChecked == true ? Visibility.Collapsed : Visibility.Visible;
        ServiceCard.Visibility = ShowPrograms.IsChecked == true || ShowNet.IsChecked == true ? Visibility.Collapsed : Visibility.Visible;
        AutoCard.Visibility = ShowAll.IsChecked == true ? Visibility.Visible : Visibility.Collapsed;
        AutoList.ItemsSource = AutoRows();

        foreach (var list in Lists)
        {
            ApplySort(list);
        }

        UpdateGlance(allPrograms, allServices);
        UpdateSelection();

        var allowed = allPrograms.Count(r => r.Action == "allow");
        Subtitle = _model.Status is null
            ? (_model.Error ?? "The CrioFire service is not running.")
            : $"{allowed} programs allowed, {allPrograms.Count - allowed} blocked, {allNet.Count} port and address rules, {allServices.Count} service rules.";
    }

    private static string Count(string title, int shown, int total) =>
        shown == total ? $"{title} ({total})" : $"{title} ({shown} of {total})";

    /// <summary>" (SMB (file sharing))" for "445", nothing for several ports or unknown ones.</summary>
    private static string PortNames(string ports) =>
        ushort.TryParse(ports, out var port) && NetworkFacts.PortName(port) is { } name ? $" ({name})" : string.Empty;

    private void UpdateGlance(List<RuleInfo> programs, List<RuleInfo> services)
    {
        var blocked = RuleViews.Blocked(_model.Rules);
        var ports = blocked.Where(b => b.Kind == "port").ToList();
        var addresses = blocked.Where(b => b.Kind == "address").ToList();
        BlockedPorts.ItemsSource = ports;
        BlockedAddresses.ItemsSource = addresses;
        NoPorts.Visibility = ports.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        NoAddresses.Visibility = addresses.Count == 0 ? Visibility.Visible : Visibility.Collapsed;

        var blockedPrograms = programs.Where(r => r.Action == "block").Select(r => r.App?.ToUpperInvariant()).Distinct().Count();
        var blockedServices = services.Count(r => r.Action == "block");
        var mode = _model.PanicMode switch
        {
            "block" => "Panic is on: all network traffic is blocked, whatever the rules say.",
            "allow" => "Panic is on: everything is allowed and these rules are paused.",
            _ => _model.Mode == "learning"
                ? "Learning mode: programs without a rule may connect."
                : $"{AppModel.ModeName(_model.Mode)} mode: programs without a rule are blocked when they connect out.",
        };
        GlanceText.Text = $"{mode} By rule: {blockedPrograms} program{(blockedPrograms == 1 ? string.Empty : "s")}, "
            + $"{blockedServices} service{(blockedServices == 1 ? string.Empty : "s")}, {ports.Count} port{(ports.Count == 1 ? string.Empty : "s")} "
            + $"and {addresses.Count} address{(addresses.Count == 1 ? string.Empty : "es")} blocked.";
    }

    // ---- sorting ----

    private void OnHeaderClick(object sender, RoutedEventArgs e)
    {
        if (sender is not ListView list || e.OriginalSource is not GridViewColumnHeader { Column: { } column })
        {
            return;
        }

        var header = Plain(column.Header as string);
        var property = header switch
        {
            "ACTION" => "Action",
            "DIRECTION" => "Direction",
            "PROGRAM" => "Program",
            "UNTIL" => "Until",
            "RULE" => "Rule",
            "SERVICE" => "DisplayName",
            _ => null,
        };
        if (property is null)
        {
            return;
        }

        var direction = _sort.TryGetValue(list, out var current) && current.Property == property && current.Direction == ListSortDirection.Ascending
            ? ListSortDirection.Descending
            : ListSortDirection.Ascending;
        _sort[list] = (property, direction);
        ApplySort(list);
    }

    private void ApplySort(ListView list)
    {
        if (list.View is GridView grid)
        {
            foreach (var column in grid.Columns)
            {
                var plain = Plain(column.Header as string);
                var sorted = _sort.TryGetValue(list, out var s) && HeaderFor(s.Property) == plain;
                column.Header = sorted ? $"{plain} {(s.Direction == ListSortDirection.Ascending ? "▲" : "▼")}" : plain;
            }
        }

        if (list.ItemsSource is null || !_sort.TryGetValue(list, out var sort))
        {
            return;
        }

        var view = CollectionViewSource.GetDefaultView(list.ItemsSource);
        view.SortDescriptions.Clear();
        view.SortDescriptions.Add(new SortDescription(sort.Property, sort.Direction));
    }

    private static string Plain(string? header) => (header ?? string.Empty).Replace(" ▲", string.Empty, StringComparison.Ordinal).Replace(" ▼", string.Empty, StringComparison.Ordinal);

    private static string HeaderFor(string property) => property switch
    {
        "Action" => "ACTION",
        "Direction" => "DIRECTION",
        "Program" => "PROGRAM",
        "Until" => "UNTIL",
        "Rule" => "RULE",
        "DisplayName" => "SERVICE",
        _ => string.Empty,
    };

    // ---- selection, switching, removing ----

    private List<RuleInfo> SelectedRules() => Lists
        .SelectMany(l => l.SelectedItems.Cast<object>())
        .Select(Info)
        .OfType<RuleInfo>()
        .ToList();

    private static RuleInfo? Info(object row) => row switch
    {
        RuleRow r => r.Info,
        NetRuleRow n => n.Info,
        ServiceRuleRow s => s.Info,
        _ => null,
    };

    private void UpdateSelection()
    {
        var count = SelectedRules().Count;
        SelectionText.Text = count switch
        {
            0 => "Click Allow or Block in a row to switch it. Click a column heading to sort; Ctrl or Shift selects several rules.",
            1 => "1 rule selected.",
            _ => $"{count} rules selected: Switch and Remove apply to all of them.",
        };
    }

    private void OnSelectionChanged(object sender, SelectionChangedEventArgs e) => UpdateSelection();

    /// <summary>The Allow/Block chip in a row: switch that rule.</summary>
    private void OnFlip(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement { Tag: RuleInfo rule })
        {
            _model.ChangeRules([rule], RuleViews.Opposite(rule.Action), null);
        }
    }

    private void OnSwitchAllow(object sender, RoutedEventArgs e) => SwitchSelected("allow");

    private void OnSwitchBlock(object sender, RoutedEventArgs e) => SwitchSelected("block");

    private void SwitchSelected(string action)
    {
        var rules = SelectedRules();
        if (rules.Count == 0)
        {
            _model.Say("Select one or more rules first.");
            return;
        }

        _model.ChangeRules(rules, action, null);
    }

    private void OnRemove(object sender, RoutedEventArgs e)
    {
        var rules = SelectedRules();
        if (rules.Count == 0)
        {
            _model.Say("Select a rule in the list first.");
            return;
        }

        if (rules.Count > 1 && Window.GetWindow(this) is { } owner
            && ChoiceDialog.Ask(owner, $"Remove {rules.Count} rules?", "The programs, ports, addresses and services they cover go back to what the mode decides.",
                [$"Remove {rules.Count} rules", "Cancel"], defaultIndex: 1, danger: true) != 0)
        {
            return;
        }

        _model.RemoveMany(rules);
    }

    private void OnMenuOpening(ContextMenu menu, ContextMenuEventArgs e)
    {
        var rules = SelectedRules();
        var owner = Window.GetWindow(this);
        if (rules.Count == 0 || owner is null)
        {
            e.Handled = true;
            return;
        }

        menu.Items.Clear();
        var first = rules[0];
        var many = rules.Count > 1;
        menu.Items.Add(new MenuItem
        {
            Header = many ? $"{rules.Count} rules" : first.Service is { } s ? $"Service {s}" : first.App is { } a ? KnownApps.DisplayName(a) : first.Summary ?? first.Name,
            IsHitTestVisible = false,
            Focusable = false,
            FontWeight = FontWeights.SemiBold,
        });
        menu.Items.Add(Item("Switch to Allow", () => _model.ChangeRules(rules, "allow", null), enabled: rules.Any(r => r.Action != "allow")));
        menu.Items.Add(Item("Switch to Block", () => _model.ChangeRules(rules, "block", null), enabled: rules.Any(r => r.Action != "block"), danger: true));
        menu.Items.Add(new Separator());
        menu.Items.Add(Item("Outbound only", () => _model.ChangeRules(rules, null, "out"), enabled: rules.Any(r => r.Direction != "out")));
        menu.Items.Add(Item("Inbound only", () => _model.ChangeRules(rules, null, "in"), enabled: rules.Any(r => r.Direction != "in")));
        menu.Items.Add(Item("In and out", () => _model.ChangeRules(rules, null, "both"), enabled: rules.Any(r => r.Direction != "both")));
        menu.Items.Add(new Separator());
        var networks = new MenuItem { Header = "Networks", ToolTip = "Which kinds of network the rule applies on. On other networks, the mode decides." };
        networks.Items.Add(Item("Every network", () => _model.ChangeRules(rules, null, null, "any"), enabled: rules.Any(r => r.Networks is not null)));
        networks.Items.Add(Item("Only home and work networks (private, domain)", () => _model.ChangeRules(rules, null, null, "domain,private"),
            enabled: rules.Any(r => r.Networks != "domain,private")));
        networks.Items.Add(Item("Only public networks", () => _model.ChangeRules(rules, null, null, "public"), enabled: rules.Any(r => r.Networks != "public")));
        menu.Items.Add(networks);
        menu.Items.Add(new Separator());
        if (!many && (first.App is not null || first.Service is not null))
        {
            menu.Items.Add(Item("Show its connections", () => _model.OpenActivity(first.Service is { } service
                ? new ActivityQuery("all", Service: service)
                : new ActivityQuery("all", App: first.App))));
            menu.Items.Add(Item("More info…", () => DetailsWindow.Open(owner, _model, new MenuTarget(first.App, first.Service))));
            menu.Items.Add(Item("Open file location", () => RowMenu.OpenFolder(first.App), enabled: first.App is not null && File.Exists(first.App)));
            menu.Items.Add(new Separator());
        }

        menu.Items.Add(Item(many ? $"Remove {rules.Count} rules" : "Remove", () => OnRemove(this, new RoutedEventArgs()), danger: true));
        menu.Items.Add(Item("Copy", () => RowMenu.Copy(_model, string.Join(Environment.NewLine, rules.Select(Describe)))));
    }

    private static string Describe(RuleInfo r) =>
        $"{r.Action} {r.Direction}: " + (r.Service is { } s ? $"service {s}" : r.Summary is { } summary ? $"{summary}{(r.App is null ? string.Empty : $" ({r.App})")}" : r.App ?? r.Name);

    private static MenuItem Item(string header, Action action, bool enabled = true, bool danger = false)
    {
        var item = new MenuItem { Header = header, IsEnabled = enabled };
        if (danger)
        {
            item.SetResourceReference(ForegroundProperty, "FireTextBrush");
        }

        item.Click += (_, _) => action();
        return item;
    }

    // ---- filters ----

    private void OnFilterChanged(object sender, RoutedEventArgs e)
    {
        if (IsLoaded)
        {
            _model.NotifyChanged();
        }
    }

    private void OnClearFilters(object sender, RoutedEventArgs e)
    {
        SearchBox.Text = string.Empty;
        ActionAll.IsChecked = true;
        DirAny.IsChecked = true;
        ShowAll.IsChecked = true;
        _model.NotifyChanged();
    }

    /// <summary>A blocked port or address at the top: show only the rules for it.</summary>
    private void OnGlanceChip(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement { Tag: string value })
        {
            SearchBox.Text = value.Split('-')[0];
            ActionBlock.IsChecked = true;
            ShowNet.IsChecked = true;
            _model.NotifyChanged();
        }
    }

    private List<AutoRuleRow> AutoRows()
    {
        var learning = _model.Mode == "learning";
        string State(AutoRuleInfo? r) => r is null ? "unknown" : !r.Enabled ? "Off" : r.Active ? "On" : "On in Ask and Allow-list modes";
        var services = _model.AutoRules.FirstOrDefault(r => r.Name == AutoRulePolicy.WindowsServices);
        var kernel = _model.AutoRules.FirstOrDefault(r => r.Name == AutoRulePolicy.WindowsKernel);
        var known = _model.Status is not null;
        return
        [
            new AutoRuleRow(AutoRulePolicy.WindowsServices, "Windows services (svchost.exe)",
                "DNS name lookups, DHCP, Windows Update, time sync and other services hosted in svchost.exe may connect out.",
                State(services), known, services?.Enabled ?? true),
            new AutoRuleRow(AutoRulePolicy.WindowsKernel, "Windows kernel (System)",
                "Kernel-mode traffic such as file and printer sharing (SMB), NetBIOS and ICMP may connect out.",
                State(kernel), known, kernel?.Enabled ?? true),
            new AutoRuleRow("loopback", "Local traffic (loopback)",
                "Programs on this PC may talk to each other over 127.0.0.1 and ::1. A block rule for a program still stops its local traffic too.",
                "Always on", false, true),
            new AutoRuleRow("inbound", "Inbound connections",
                "Connections from other machines are left to Windows Firewall unless you add inbound rules for a program, a service or a port.",
                "Windows Firewall", false, true),
            new AutoRuleRow("learning", "Programs without a rule",
                learning ? "Learning mode: every program without a rule may connect out." : "Blocked in Ask and Allow-list modes.",
                learning ? "Allowed (Learning mode)" : "Blocked", false, learning),
        ];
    }

    private Dictionary<string, string>? _displayNames;

    /// <summary>The service list is the slow part of this page; it is read off the UI thread.</summary>
    public async Task LoadAsync() => _displayNames = await Task.Run(ServiceDisplayNames);

    private static Dictionary<string, string> ServiceDisplayNames()
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var s in WindowsServiceList.Read())
        {
            result[s.Name] = s.DisplayName;
        }

        return result;
    }

    private void OnAutoSwitch(object sender, RoutedEventArgs e)
    {
        if (sender is CheckBox { Tag: string name } box && AutoRulePolicy.IsKnown(name) && Window.GetWindow(this) is { } owner)
        {
            _model.SetAutoRule(owner, name, box.IsChecked == true);
        }
    }

    private void OnAddService(object sender, RoutedEventArgs e)
    {
        if (Window.GetWindow(this) is { } owner && ServiceRuleDialog.Ask(owner) is { } choice)
        {
            _model.SetServiceRule(choice.Service, choice.Action, choice.Direction, choice.Networks);
        }
    }

    private void OnAllow(object sender, RoutedEventArgs e) => Add("allow", null);

    private void OnAllowHour(object sender, RoutedEventArgs e) => Add("allow", 60);

    private void OnBlock(object sender, RoutedEventArgs e) => Add("block", null);

    private static string Organization(RuleInfo r) => r.Managed ? " · set by your organization" : string.Empty;

    /// <summary>" · public networks" for a rule on some networks only; nothing for every network.</summary>
    private static string Networks(RuleInfo r) =>
        r.Networks is { } text && NetworkScope.TryParse(text, out var n) && n != NetworkProfiles.Any ? " · " + NetworkScope.Label(n) : string.Empty;

    private StackPanel BuildActions()
    {
        var export = new Button { Content = "Export...", Style = (Style)FindResource("GhostButton"), Margin = new Thickness(0, 0, 8, 0), ToolTip = "Save every rule to a file" };
        export.Click += (_, _) => ExportRules();
        var import = new Button { Content = "Import...", Style = (Style)FindResource("GhostButton"), ToolTip = "Add or replace rules from a file" };
        import.Click += (_, _) => ImportRules();
        return new StackPanel { Orientation = Orientation.Horizontal, Children = { export, import } };
    }

    private void ExportRules()
    {
        var dialog = new SaveFileDialog
        {
            Title = "Export rules",
            Filter = "CrioFire rules (*.json)|*.json",
            FileName = $"criofire-rules-{Environment.MachineName}-{DateTime.Now:yyyy-MM-dd}.json",
        };
        if (dialog.ShowDialog(Window.GetWindow(this)) != true || _model.ExportRules() is not { } set)
        {
            return;
        }

        try
        {
            File.WriteAllText(dialog.FileName, RuleBackup.ToJson(set));
            _model.Say($"Saved {set.Count} rules to {Path.GetFileName(dialog.FileName)}.");
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            _model.Say($"Could not save the file: {ex.Message}");
        }
    }

    private void ImportRules()
    {
        var owner = Window.GetWindow(this);
        var dialog = new OpenFileDialog { Title = "Import rules", Filter = "CrioFire rules (*.json)|*.json" };
        if (owner is null || dialog.ShowDialog(owner) != true)
        {
            return;
        }

        RuleSet set;
        try
        {
            set = RuleBackup.FromJson(File.ReadAllText(dialog.FileName));
        }
        catch (Exception ex) when (ex is ArgumentException or IOException or UnauthorizedAccessException)
        {
            _model.Say(ex.Message);
            return;
        }

        if (_model.PlanImport(set, "merge") is not { } merge || _model.PlanImport(set, "replace") is not { } replace)
        {
            return;
        }

        var from = set.Computer is { Length: > 0 } pc ? $" from {pc}" : string.Empty;
        var missing = merge.Missing.Count == 0 ? string.Empty
            : $"\n\n{merge.Missing.Count} program(s) in the file are not on this PC and are skipped, e.g. {merge.Missing[0]}.";
        var message =
            $"The file has {set.Count} rules{from}.\n\n"
            + $"Merge: adds {merge.Add}, changes {merge.Change}, keeps your other rules.\n"
            + $"Replace: the same, and removes {replace.Remove} rule(s) that are not in the file."
            + missing
            + "\n\nYour current rules are saved as a backup first (Settings, Rule backups). The mode is not changed.";
        var choice = ChoiceDialog.Ask(owner, "Import rules?", message, ["Merge", "Replace", "Cancel"], defaultIndex: 0);
        if (choice is 0 or 1)
        {
            _model.ImportRules(set, choice == 0 ? "merge" : "replace");
        }
    }

    private void Add(string action, int? minutes)
    {
        var dialog = new OpenFileDialog { Filter = "Programs (*.exe)|*.exe", Title = action == "allow" ? "Choose a program to allow" : "Choose a program to block" };
        if (dialog.ShowDialog(Window.GetWindow(this)) == true)
        {
            _model.SetRule(dialog.FileName, action, minutes);
        }
    }

    private void OnAddNet(object sender, RoutedEventArgs e)
    {
        if (Window.GetWindow(this) is { } owner && NetRuleDialog.Ask(owner) is { } rule)
        {
            _model.AddNetRule(rule);
        }
    }
}
