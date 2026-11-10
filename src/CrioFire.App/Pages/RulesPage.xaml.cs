using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
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
                    Bars.Name(r.App),
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

        var allowed = rows.Count(r => r.Action == "Allow");
        Subtitle = _model.Status is null
            ? (_model.Error ?? "The CrioFire service is not running.")
            : $"{allowed} programs allowed, {rows.Count - allowed} blocked, {netRows.Count} network rules.";
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
        }
    }

    private void OnNetSelected(object sender, SelectionChangedEventArgs e)
    {
        if (NetTable.SelectedItem is not null)
        {
            Table.SelectedItem = null;
        }
    }

    private void OnRemove(object sender, RoutedEventArgs e)
    {
        if (NetTable.SelectedItem is NetRuleRow net)
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
