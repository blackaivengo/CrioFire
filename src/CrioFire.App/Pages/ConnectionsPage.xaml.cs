using System.Windows;
using System.Windows.Controls;
using CrioFire.Core;

namespace CrioFire.App.Pages;

/// <summary>
/// Live TCP and UDP connections with the program, and for svchost.exe the Windows services, that
/// own each; allow or block any of them. Reading needs no administrator rights.
/// </summary>
public partial class ConnectionsPage : UserControl, IPage
{
    private readonly AppModel _model;

    internal ConnectionsPage(AppModel model)
    {
        _model = model;
        InitializeComponent();
        RowMenu.Attach(Table, model, RowMenu.From);
    }

    public string Title => "Live connections";

    public string Subtitle { get; private set; } = string.Empty;

    public FrameworkElement? Actions => null;

    public TimeSpan? AutoRefresh => TimeSpan.FromSeconds(3);

    public void Refresh()
    {
        var all = ShowAll.IsChecked == true;
        var selected = Table.SelectedItem as LiveRow;
        var connections = ConnectionTable.Read();
        var services = WindowsServiceList.ByProcess(WindowsServiceList.Read());
        var rows = connections
            .Where(c => all || c.Remote is not null)
            .OrderBy(c => c.ProcessPath is null)
            .ThenBy(c => c.ProcessPath, StringComparer.OrdinalIgnoreCase)
            .ThenBy(c => c.Local.Port)
            .Select(c => LiveRow.From(c, services))
            .ToList();
        Table.ItemsSource = rows;
        if (selected is not null)
        {
            Table.SelectedItem = rows.FirstOrDefault(r => r.ProcessId == selected.ProcessId && r.Local == selected.Local && r.Remote == selected.Remote);
        }

        var programs = rows.Select(r => r.ProcessId).Distinct().Count();
        Subtitle = $"{Fmt.Count(rows.Count)} {(all ? "sockets" : "connections")} from {programs} programs. Updates every 3 seconds.";
    }

    private void OnShow(object sender, RoutedEventArgs e) => Refresh();

    private void OnAllow(object sender, RoutedEventArgs e) => Decide("allow");

    private void OnBlock(object sender, RoutedEventArgs e) => Decide("block");

    private void Decide(string action)
    {
        if (Table.SelectedItem is not LiveRow row)
        {
            _model.Say("Select a connection in the list first.");
            return;
        }

        var app = row.ProcessId == 4 ? KnownApps.Kernel : row.Path;
        if (row.ProcessId != 4 && !System.IO.Path.IsPathRooted(app))
        {
            _model.Say("CrioFire can't see this program's path (it runs as another user). Open CrioFire as administrator to make a rule for it.");
            return;
        }

        if (Window.GetWindow(this) is { } owner)
        {
            _model.Decide(owner, app, row.Services.Length == 0 ? null : row.Services, action);
        }
    }
}
