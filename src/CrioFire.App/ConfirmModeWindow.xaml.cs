using System.Globalization;
using System.Windows;
using System.Windows.Threading;

namespace CrioFire.App;

/// <summary>After switching to a blocking mode: keep it only if the user confirms within 60 seconds.</summary>
public partial class ConfirmModeWindow : Window
{
    private const int Seconds = 60;
    private readonly DispatcherTimer _timer = new() { Interval = TimeSpan.FromSeconds(1) };
    private int _secondsLeft = Seconds;

    public ConfirmModeWindow()
    {
        InitializeComponent();
        UpdateCountdown();
        _timer.Tick += (_, _) =>
        {
            _secondsLeft--;
            UpdateCountdown();
            if (_secondsLeft <= 0)
            {
                _timer.Stop();
                DialogResult = false;
            }
        };
        Loaded += (_, _) => _timer.Start();
        Closed += (_, _) => _timer.Stop();
    }

    private void UpdateCountdown()
    {
        SecondsText.Text = _secondsLeft.ToString(CultureInfo.CurrentCulture);
        CountdownArc.Data = Arcs.Arc((double)_secondsLeft / Seconds, 32, 29.5);
    }

    private void OnKeep(object sender, RoutedEventArgs e) => DialogResult = true;
}
