using System.Windows;
using System.Windows.Threading;

namespace CrioFire.App;

/// <summary>After switching to a blocking mode: keep it only if the user confirms within 60 seconds.</summary>
public partial class ConfirmModeWindow : Window
{
    private readonly DispatcherTimer _timer = new() { Interval = TimeSpan.FromSeconds(1) };
    private int _secondsLeft = 60;

    public ConfirmModeWindow()
    {
        InitializeComponent();
        UpdateText();
        _timer.Tick += (_, _) =>
        {
            _secondsLeft--;
            UpdateText();
            if (_secondsLeft <= 0)
            {
                _timer.Stop();
                DialogResult = false;
            }
        };
        Loaded += (_, _) => _timer.Start();
        Closed += (_, _) => _timer.Stop();
    }

    private void UpdateText() => CountdownText.Text = $"Switching back in {_secondsLeft} seconds.";

    private void OnKeep(object sender, RoutedEventArgs e) => DialogResult = true;
}
