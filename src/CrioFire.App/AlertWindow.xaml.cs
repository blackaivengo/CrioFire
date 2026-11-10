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
    private static int _open;

    public AlertWindow(EventInfo blocked)
    {
        ArgumentNullException.ThrowIfNull(blocked);
        InitializeComponent();
        Headline.Text = $"{Path.GetFileName(blocked.App) ?? "A program"} wants to connect";
        Details.Text = $"{blocked.Protocol} → {blocked.Remote ?? "unknown address"} · {blocked.App}";
        Details.ToolTip = blocked.App;

        // Stack in the bottom-right corner of the work area, like notifications.
        var slot = _open++;
        Loaded += (_, _) =>
        {
            var area = SystemParameters.WorkArea;
            Left = area.Right - ActualWidth;
            Top = Math.Max(area.Top, area.Bottom - ((slot + 1) * (ActualHeight - 30)) - 10);
        };
        Closed += (_, _) => _open = Math.Max(0, _open - 1);
    }

    public AlertChoice Choice { get; private set; } = AlertChoice.None;

    /// <summary>Closes the alert because the decision was made elsewhere (e.g. on the dashboard).</summary>
    public void Dismiss(AlertChoice choice)
    {
        Choice = choice;
        Close();
    }

    private void OnAllow(object sender, RoutedEventArgs e) => Dismiss(AlertChoice.Allow);

    private void OnAllowOneHour(object sender, RoutedEventArgs e) => Dismiss(AlertChoice.AllowOneHour);

    private void OnBlock(object sender, RoutedEventArgs e) => Dismiss(AlertChoice.Block);

    private void OnNotNow(object sender, RoutedEventArgs e) => Dismiss(AlertChoice.None);
}
