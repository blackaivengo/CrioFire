using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Shapes;

namespace CrioFire.App;

/// <summary>
/// The welcome tour: what CrioFire does, the mode, starting with Windows, and what to do if
/// something goes wrong. It only collects the choices; <see cref="AppModel.ShowWelcome"/> applies
/// them when the user finishes (Skip or Escape changes nothing).
/// </summary>
public partial class WelcomeWindow : Window
{
    private readonly StackPanel[] _pages;
    private int _page;

    /// <param name="mode">The current mode, chosen at first.</param>
    /// <param name="canSetMode">False while the service is not running or not set up: the modes are shown, not offered.</param>
    /// <param name="startWithWindows">Whether the app starts at sign-in now.</param>
    public WelcomeWindow(string mode, bool canSetMode, bool startWithWindows)
    {
        InitializeComponent();
        _pages = [PageWelcome, PageMode, PageStartup, PageHelp];
        (mode switch { "ask" => ModeAsk, "allowlist" => ModeAllowList, _ => ModeLearning }).IsChecked = true;
        ModeLearning.IsEnabled = ModeAsk.IsEnabled = ModeAllowList.IsEnabled = canSetMode;
        AutostartBox.IsChecked = startWithWindows;

        MouseLeftButtonDown += (_, e) =>
        {
            if (e.ButtonState == MouseButtonState.Pressed)
            {
                DragMove();
            }
        };
        Loaded += (_, _) => ShowPage(0);
    }

    /// <summary>The mode picked on the second page.</summary>
    public string Mode => ModeAsk.IsChecked == true ? "ask" : ModeAllowList.IsChecked == true ? "allowlist" : "learning";

    /// <summary>The "Start CrioFire when I sign in to Windows" switch.</summary>
    public bool StartWithWindows => AutostartBox.IsChecked == true;

    private void OnNext(object sender, RoutedEventArgs e)
    {
        if (_page == _pages.Length - 1)
        {
            DialogResult = true;   // finished: apply the choices
        }
        else
        {
            ShowPage(_page + 1);
        }
    }

    private void OnBack(object sender, RoutedEventArgs e) => ShowPage(Math.Max(0, _page - 1));

    private void ShowPage(int page)
    {
        _page = page;
        for (var i = 0; i < _pages.Length; i++)
        {
            _pages[i].Visibility = i == page ? Visibility.Visible : Visibility.Collapsed;
        }

        var dots = Dots.Children.OfType<Ellipse>().ToList();
        for (var i = 0; i < dots.Count; i++)
        {
            dots[i].SetResourceReference(Shape.FillProperty, i == page ? "FocusBrush" : "TrackBrush");
        }

        BackButton.Visibility = page == 0 ? Visibility.Collapsed : Visibility.Visible;
        NextButton.Content = page == _pages.Length - 1 ? L.T("Get started") : L.T("Next");

        // The keyboard lands on the page's choice (the mode) or on Next; screen readers hear the page.
        var chosen = page == 1 ? new[] { ModeLearning, ModeAsk, ModeAllowList }.FirstOrDefault(r => r.IsChecked == true && r.IsEnabled) : null;
        Dispatcher.BeginInvoke(() => ((UIElement?)chosen ?? NextButton).Focus(), System.Windows.Threading.DispatcherPriority.Input);
        ScreenReader.Say(this, string.Join(" ", _pages[page].Children.OfType<TextBlock>().Select(t => t.Text)));
    }
}
