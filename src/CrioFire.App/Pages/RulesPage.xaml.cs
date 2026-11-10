using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using CrioFire.Core;
using CrioFire.Core.Api;
using Microsoft.Win32;

namespace CrioFire.App.Pages;

/// <summary>The programs the user allowed or blocked, with add and remove.</summary>
public partial class RulesPage : UserControl, IPage
{
    private readonly AppModel _model;

    internal RulesPage(AppModel model)
    {
        _model = model;
        InitializeComponent();
    }

    public string Title => "Rules";

    public string Subtitle { get; private set; } = string.Empty;

    public FrameworkElement? Actions => null;

    public TimeSpan? AutoRefresh => null;

    public void Refresh()
    {
        var chipFire = (Brush)FindResource("ChipFireBrush");
        var chipFireText = (Brush)FindResource("ChipFireTextBrush");
        var chipIce = (Brush)FindResource("ChipIceBrush");
        var chipIceText = (Brush)FindResource("ChipIceTextBrush");
        var rows = _model.AppRules
            .OrderBy(r => r.Action)
            .ThenBy(r => Bars.Name(r.App), StringComparer.OrdinalIgnoreCase)
            .Select(r =>
            {
                var allow = r.Action == "allow";
                return new RuleRow(
                    allow ? "Allow" : "Block",
                    r.Direction switch { "in" => "Inbound", "both" => "Both", _ => "Outbound" },
                    KnownApps.DisplayName(r.App),
                    r.App ?? r.Name,
                    r.ExpiresUtc is DateTime t ? Fmt.Time(t) : "always",
                    allow ? chipIce : chipFire,
                    allow ? chipIceText : chipFireText);
            })
            .ToList();
        Table.ItemsSource = rows;
        Empty.Visibility = rows.Count == 0 ? Visibility.Visible : Visibility.Collapsed;

        var netRows = _model.NetRules
            .OrderBy(r => r.Action)
            .ThenBy(r => r.Summary, StringComparer.OrdinalIgnoreCase)
            .Select(r =>
            {
                var allow = r.Action == "allow";
                var rule = string.Join(" · ", new[]
                {
                    r.Protocol is null or "any" ? null : r.Protocol.ToUpperInvariant(),
                    r.Ports is null ? null : (r.Direction == "in" ? "local port " : "port ") + r.Ports,
                    r.Addresses,
                }.Where(p => p is not null));
                return new NetRuleRow(
                    allow ? "Allow" : "Block",
                    r.Direction switch { "in" => "Inbound", "both" => "Both", _ => "Outbound" },
                    rule,
                    r.App is null ? "Any program" : Bars.Name(r.App),
                    r.App,
                    r.FilterId,
                    allow ? chipIce : chipFire,
                    allow ? chipIceText : chipFireText);
            })
            .ToList();
        NetTable.ItemsSource = netRows;
        NetEmpty.Visibility = netRows.Count == 0 ? Visibility.Visible : Visibility.Collapsed;

        var displayNames = ServiceDisplayNames();
        var serviceRows = _model.ServiceRules
            .OrderBy(r => r.Action)
            .ThenBy(r => r.Service, StringComparer.OrdinalIgnoreCase)
            .Select(r =>
            {
                var allow = r.Action == "allow";
                var service = r.Service ?? "?";
                return new ServiceRuleRow(
                    allow ? "Allow" : "Block",
                    Who.Direction(r.Direction),
                    service,
                    displayNames.TryGetValue(service, out var display) ? display : service,
                    allow ? chipIce : chipFire,
                    allow ? chipIceText : chipFireText);
            })
            .ToList();
        ServiceTable.ItemsSource = serviceRows;
        ServiceEmpty.Visibility = serviceRows.Count == 0 ? Visibility.Visible : Visibility.Collapsed;

        AutoList.ItemsSource = AutoRows();

        var allowed = rows.Count(r => r.Action == "Allow");
        Subtitle = _model.Status is null
            ? (_model.Error ?? "The CrioFire service is not running.")
            : $"{allowed} programs allowed, {rows.Count - allowed} blocked, {netRows.Count} network rules, {serviceRows.Count} service rules.";
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
            _model.SetServiceRule(choice.Service, choice.Action, choice.Direction);
        }
    }

    private void OnServiceSelected(object sender, SelectionChangedEventArgs e)
    {
        if (ServiceTable.SelectedItem is not null)
        {
            Table.SelectedItem = null;
            NetTable.SelectedItem = null;
        }
    }

    private void OnAllow(object sender, RoutedEventArgs e) => Add("allow", null);

    private void OnAllowHour(object sender, RoutedEventArgs e) => Add("allow", 60);

    private void OnBlock(object sender, RoutedEventArgs e) => Add("block", null);

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

    private void OnProgramSelected(object sender, SelectionChangedEventArgs e)
    {
        if (Table.SelectedItem is not null)
        {
            NetTable.SelectedItem = null;
            ServiceTable.SelectedItem = null;
        }
    }

    private void OnNetSelected(object sender, SelectionChangedEventArgs e)
    {
        if (NetTable.SelectedItem is not null)
        {
            Table.SelectedItem = null;
            ServiceTable.SelectedItem = null;
        }
    }

    private void OnRemove(object sender, RoutedEventArgs e)
    {
        if (ServiceTable.SelectedItem is ServiceRuleRow service)
        {
            _model.RemoveServiceRules(service.Service);
        }
        else if (NetTable.SelectedItem is NetRuleRow net)
        {
            _model.RemoveNetRule(net.FilterId, net.Rule);
        }
        else if (Table.SelectedItem is RuleRow row)
        {
            _model.RemoveRules(row.App);
        }
        else
        {
            _model.Say("Select a rule in the list first.");
        }
    }
}
