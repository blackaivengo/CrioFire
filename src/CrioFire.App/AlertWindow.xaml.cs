using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;
using CrioFire.Core;
using CrioFire.Core.Api;

namespace CrioFire.App;

public enum AlertChoice
{
    None,
    Allow,
    AllowFor,
    Block,
}

/// <summary>
/// Asks the user about a program the Ask-mode catch-all block stopped. Closing it means "not now".
/// The timed allow button defaults to one hour; pressing and holding it pops up other durations.
/// Releasing over one picks it, and a second press confirms.
/// </summary>
public partial class AlertWindow : Window
{
    private static readonly (int Minutes, string Option, string Button)[] Durations =
    [
        (15, "15 minutes", "Allow 15 min"),
        (30, "30 minutes", "Allow 30 min"),
        (60, "1 hour", "Allow 1 hour"),
        (24 * 60, "24 hours", "Allow 24 hours"),
    ];

    private static int _open;
    private readonly DispatcherTimer _hold = new() { Interval = TimeSpan.FromMilliseconds(350) };
    private bool _pressed;

    public AlertWindow(EventInfo blocked)
    {
        ArgumentNullException.ThrowIfNull(blocked);
        InitializeComponent();
        Headline.Text = L.T($"{Path.GetFileName(blocked.App) ?? L.T("A program")} wants to connect");
        Details.Text = $"{blocked.Protocol} → {blocked.Remote ?? "unknown address"} · {blocked.App}";
        Details.ToolTip = blocked.App;

        foreach (var (minutes, option, _) in Durations)
        {
            var item = new Button
            {
                Content = option,
                Tag = minutes,
                Style = (Style)FindResource("GhostButton"),
                HorizontalContentAlignment = HorizontalAlignment.Left,
                MinHeight = 38,
                Padding = new Thickness(14, 0, 14, 0),
            };
            item.Click += (_, _) => Choose(minutes);
            DurationPanel.Children.Add(item);
        }

        UpdateDurations(null);

        _hold.Tick += (_, _) =>
        {
            _hold.Stop();
            if (_pressed)
            {
                DurationPopup.IsOpen = true;
            }
        };

        // Stack in the bottom-right corner of the work area, like notifications.
        var slot = _open++;
        Loaded += (_, _) =>
        {
            var area = SystemParameters.WorkArea;
            Left = area.Right - ActualWidth;
            Top = Math.Max(area.Top, area.Bottom - ((slot + 1) * (ActualHeight - 30)) - 10);
        };
        Deactivated += (_, _) => DurationPopup.IsOpen = false;
        PreviewMouseDown += (_, e) =>
        {
            if (DurationPopup.IsOpen && !TimedButton.IsMouseCaptured && e.OriginalSource is DependencyObject d
                && !IsInside(d, TimedButton) && !IsInside(d, DurationPanel))
            {
                DurationPopup.IsOpen = false;
            }
        };
        PreviewKeyDown += (_, e) =>
        {
            if (e.Key == Key.Escape && DurationPopup.IsOpen)
            {
                DurationPopup.IsOpen = false;
                TimedButton.Focus();
                e.Handled = true;
            }
        };
        Closed += (_, _) =>
        {
            _hold.Stop();
            DurationPopup.IsOpen = false;
            _open = Math.Max(0, _open - 1);
        };
    }

    public AlertChoice Choice { get; private set; } = AlertChoice.None;

    /// <summary>For <see cref="AlertChoice.AllowFor"/>: how long the rule lasts.</summary>
    public int Minutes { get; private set; } = 60;

    /// <summary>Closes the alert because the decision was made elsewhere (e.g. on the dashboard).</summary>
    public void Dismiss(AlertChoice choice)
    {
        Choice = choice;
        Close();
    }

    private void OnAllow(object sender, RoutedEventArgs e) => Dismiss(AlertChoice.Allow);

    private void OnBlock(object sender, RoutedEventArgs e) => Dismiss(AlertChoice.Block);

    private void OnNotNow(object sender, RoutedEventArgs e) => Dismiss(AlertChoice.None);

    /// <summary>Keyboard (Enter/Space) confirms the duration shown.</summary>
    private void OnTimedClick(object sender, RoutedEventArgs e) => Dismiss(AlertChoice.AllowFor);

    private void OnTimedDown(object sender, MouseButtonEventArgs e)
    {
        e.Handled = true;   // we decide between "click" and "hold" ourselves
        if (DurationPopup.IsOpen)
        {
            DurationPopup.IsOpen = false;
        }

        _pressed = true;
        TimedButton.CaptureMouse();
        _hold.Start();
    }

    private void OnTimedMove(object sender, MouseEventArgs e)
    {
        if (_pressed && DurationPopup.IsOpen)
        {
            UpdateDurations(OptionUnder(e));
        }
    }

    private void OnTimedUp(object sender, MouseButtonEventArgs e)
    {
        if (!_pressed)
        {
            return;
        }

        e.Handled = true;
        _pressed = false;
        _hold.Stop();
        TimedButton.ReleaseMouseCapture();

        if (DurationPopup.IsOpen)
        {
            if (OptionUnder(e) is { Tag: int minutes })
            {
                Choose(minutes);   // picked: the button now shows it; pressing again confirms
            }
            else
            {
                UpdateDurations(null);   // released elsewhere: leave the choices open to click
            }

            return;
        }

        var p = e.GetPosition(TimedButton);
        if (p.X >= 0 && p.Y >= 0 && p.X <= TimedButton.ActualWidth && p.Y <= TimedButton.ActualHeight)
        {
            Dismiss(AlertChoice.AllowFor);   // a short press confirms the duration shown
        }
    }

    private void OnTimedKey(object sender, KeyEventArgs e)
    {
        if (e.Key is Key.Up or Key.Down || (e.Key == Key.System && e.SystemKey == Key.Down))
        {
            DurationPopup.IsOpen = true;
            UpdateDurations(null);
            Dispatcher.BeginInvoke(DispatcherPriority.Input, () => (DurationPanel.Children[0] as Button)?.Focus());
            e.Handled = true;
        }
    }

    private void Choose(int minutes)
    {
        Minutes = minutes;
        TimedText.Text = Durations.First(d => d.Minutes == minutes).Button;
        TimedButton.ToolTip = L.T("Press to confirm, or hold for more choices");
        DurationPopup.IsOpen = false;
        UpdateDurations(null);
        TimedButton.Focus();
    }

    /// <summary>Marks the current duration and the one under the pointer.</summary>
    private void UpdateDurations(Button? hovered)
    {
        foreach (Button item in DurationPanel.Children)
        {
            var current = item.Tag is int m && m == Minutes;
            item.SetResourceReference(BackgroundProperty, item == hovered ? "NavActiveBrush" : "TransparentBrush");
            item.SetResourceReference(ForegroundProperty, current ? "IceTextBrush" : "TextBrush");
            item.FontWeight = current ? FontWeights.Bold : FontWeights.SemiBold;
        }
    }

    private Button? OptionUnder(MouseEventArgs e)
    {
        var screen = TimedButton.PointToScreen(e.GetPosition(TimedButton));
        foreach (Button item in DurationPanel.Children)
        {
            if (PresentationSource.FromVisual(item) is null)
            {
                continue;
            }

            var p = item.PointFromScreen(screen);
            if (p.X >= 0 && p.Y >= 0 && p.X <= item.ActualWidth && p.Y <= item.ActualHeight)
            {
                return item;
            }
        }

        return null;
    }

    private static bool IsInside(DependencyObject element, DependencyObject container)
    {
        for (var d = element; d is not null; d = d is Visual or System.Windows.Media.Media3D.Visual3D ? VisualTreeHelper.GetParent(d) : LogicalTreeHelper.GetParent(d))
        {
            if (d == container)
            {
                return true;
            }
        }

        return false;
    }
}
