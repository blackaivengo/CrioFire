using System.IO;
using System.Windows;
using CrioFire.Core.Api;

namespace CrioFire.App;

public sealed record RuleRow(ulong FilterId, string Action, string Layer, string Program);

/// <summary>
/// Shows CrioFire's rules, read through the criofire service's local API, so the app runs as a
/// normal user. (Alerts, rule editing and live connections arrive in the next step.)
/// </summary>
public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();
        Loaded += (_, _) => Refresh();
    }

    private void OnRefresh(object sender, RoutedEventArgs e) => Refresh();

    private void Refresh()
    {
        try
        {
            using var client = CrioFireClient.TryConnect();
            if (client is null)
            {
                RulesList.ItemsSource = null;
                StatusText.Text = "The CrioFire service is not running. Start it with 'sc start criofire' from an administrator prompt.";
                return;
            }

            var status = client.Send(new ApiRequest { Op = ApiOps.Status });
            if (status.Status is not { Installed: true } info)
            {
                RulesList.ItemsSource = null;
                StatusText.Text = status.Error ?? "CrioFire is not registered with the filtering engine yet.";
                return;
            }

            var rules = client.Send(new ApiRequest { Op = ApiOps.List }).Rules ?? [];
            RulesList.ItemsSource = rules
                .Select(r => new RuleRow(r.FilterId, r.Action ?? "?", r.Layer ?? "?", r.App ?? r.Name))
                .ToList();
            StatusText.Text = $"Mode: {info.Mode}. {info.FilterCount} filters active.";
        }
        catch (IOException ex)
        {
            StatusText.Text = $"Lost the connection to the CrioFire service: {ex.Message}";
        }
    }
}
