using System.Windows;
using CrioFire.Core;

namespace CrioFire.App;

public sealed record RuleRow(ulong FilterId, string Action, string Layer, string Program);

/// <summary>
/// Prototype: reads rules straight from the filtering engine, which needs admin rights.
/// Phase 1 replaces this with calls to criofire-svc over the local API pipe, so the app
/// can run as a normal user.
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
            using var engine = WfpEngine.Open();
            if (!engine.IsInstalled())
            {
                RulesList.ItemsSource = null;
                StatusText.Text = "CrioFire is not installed yet. Run 'criofire install' from an administrator prompt.";
                return;
            }

            var rows = engine.ListFilters()
                .Select(f => new RuleRow(
                    f.FilterId,
                    f.Rule is null ? "?" : RuleDescription.ActionText(f.Rule.Action),
                    f.Layer?.Name ?? "?",
                    f.Rule?.AppPath ?? f.Name))
                .ToList();

            RulesList.ItemsSource = rows;
            StatusText.Text = $"{rows.Count} filters active.";
        }
        catch (WfpException ex) when (ex.IsAccessDenied)
        {
            StatusText.Text = "Reading rules needs administrator rights in this prototype. Right-click criofire-ui.exe and choose 'Run as administrator'.";
        }
        catch (WfpException ex)
        {
            StatusText.Text = ex.Message;
        }
    }
}
