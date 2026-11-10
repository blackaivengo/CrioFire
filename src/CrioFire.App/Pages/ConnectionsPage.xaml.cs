using System.Windows;
using System.Windows.Controls;
using CrioFire.Core;

namespace CrioFire.App.Pages;

/// <summary>Live TCP and UDP connections with the program that owns each. Needs no administrator rights.</summary>
public partial class ConnectionsPage : UserControl, IPage
{
    internal ConnectionsPage(AppModel model)
    {
        _ = model;
        InitializeComponent();
    }

    public string Title => "Live connections";

    public string Subtitle { get; private set; } = string.Empty;

    public FrameworkElement? Actions => null;

    public TimeSpan? AutoRefresh => TimeSpan.FromSeconds(3);

    public void Refresh()
    {
        var all = ShowAll.IsChecked == true;
        var connections = ConnectionTable.Read();
        var rows = connections
            .Where(c => all || c.Remote is not null)
            .OrderBy(c => c.ProcessPath is null)
            .ThenBy(c => c.ProcessPath, StringComparer.OrdinalIgnoreCase)
            .ThenBy(c => c.Local.Port)
            .Select(LiveRow.From)
            .ToList();
        Table.ItemsSource = rows;
        var programs = rows.Select(r => r.ProcessId).Distinct().Count();
        Subtitle = $"{Fmt.Count(rows.Count)} {(all ? "sockets" : "connections")} from {programs} programs. Updates every 3 seconds.";
    }

    private void OnShow(object sender, RoutedEventArgs e) => Refresh();
}
