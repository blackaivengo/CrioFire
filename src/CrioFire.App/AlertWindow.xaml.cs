using System.IO;
using System.Windows;
using CrioFire.Core.Api;

namespace CrioFire.App;

public enum AlertChoice
{
    None,
    Allow,
    AllowOneHour,
    Block,
}

/// <summary>Asks the user about a program the Ask-mode catch-all block stopped. Closing it means "not now".</summary>
public partial class AlertWindow : Window
{
    public AlertWindow(EventInfo blocked)
    {
        ArgumentNullException.ThrowIfNull(blocked);
        InitializeComponent();
        ProgramName.Text = Path.GetFileName(blocked.App) ?? "A program";
        ProgramPath.Text = blocked.App;
        Details.Text = $"{blocked.Protocol} connection to {blocked.Remote ?? "an unknown address"}";

        // Bottom-right corner of the work area, like a notification.
        Loaded += (_, _) =>
        {
            var area = SystemParameters.WorkArea;
            Left = area.Right - ActualWidth - 16;
            Top = area.Bottom - ActualHeight - 16;
        };
    }

    public AlertChoice Choice { get; private set; } = AlertChoice.None;

    private void OnAllow(object sender, RoutedEventArgs e) => Decide(AlertChoice.Allow);

    private void OnAllowOneHour(object sender, RoutedEventArgs e) => Decide(AlertChoice.AllowOneHour);

    private void OnBlock(object sender, RoutedEventArgs e) => Decide(AlertChoice.Block);

    private void Decide(AlertChoice choice)
    {
        Choice = choice;
        Close();
    }
}
