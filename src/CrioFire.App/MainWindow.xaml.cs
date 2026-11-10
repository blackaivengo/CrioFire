using System.ComponentModel;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Shapes;
using System.Windows.Threading;
using CrioFire.App.Pages;
using CrioFire.Core;
using CrioFire.Core.Api;

namespace CrioFire.App;

/// <summary>A screen of the app.</summary>
internal interface IPage
{
    string Title { get; }

    string Subtitle { get; }

    /// <summary>Optional controls shown in the header, next to the theme switch.</summary>
    FrameworkElement? Actions { get; }

    /// <summary>How often to refresh while the page is open; null = only when something changes.</summary>
    TimeSpan? AutoRefresh { get; }

    void Refresh();
}

/// <summary>
/// The CrioFire app window: sidebar, page header with the theme switch, and the pages. Everything
/// goes through the criofire service, so the app runs as a normal user. In Ask mode it also
/// raises an alert for each program the catch-all block stops.
/// </summary>
public partial class MainWindow : Window
{
    private readonly AppModel _model = new();
    private readonly AlertTracker _tracker = new();
    private readonly Dictionary<string, AlertWindow> _alerts = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, IPage> _pages = [];
    private readonly DispatcherTimer _poll = new() { Interval = TimeSpan.FromSeconds(2) };
    private readonly DispatcherTimer _pageTimer = new();
    private readonly DispatcherTimer _messageTimer = new() { Interval = TimeSpan.FromSeconds(6) };
    private IPage? _current;
    private TrayIcon? _tray;
    private bool _exiting;

    public MainWindow()
    {
        InitializeComponent();
        TitleBar.Attach(this);

        _model.Changed += (_, _) => RefreshPage();
        _model.Message += (_, text) => ShowMessage(text);
        _model.NavigateRequested += (_, page) => GoTo(page);
        _model.PendingResolved += (_, app) => CloseAlert(app);
        ThemeManager.Changed += (_, _) =>
        {
            UpdateThemeButton();
            RefreshPage();   // rows that picked theme brushes in code
        };
        UpdateThemeButton();

        _poll.Tick += (_, _) => Poll();
        _pageTimer.Tick += (_, _) => _current?.Refresh();
        _messageTimer.Tick += (_, _) =>
        {
            _messageTimer.Stop();
            MessageBar.Visibility = Visibility.Collapsed;
        };

        Closing += OnClosing;
        Closed += (_, _) =>
        {
            _poll.Stop();
            _pageTimer.Stop();
            foreach (var alert in _alerts.Values.ToList())
            {
                alert.Close();
            }

            _tray?.Dispose();
            _tray = null;
        };
    }

    /// <summary>Starts polling and the tray icon; shows the window unless starting in the tray.</summary>
    internal void Start(bool showWindow)
    {
        _tray = new TrayIcon();
        _tray.OpenRequested += (_, _) => ShowFromTray();
        _tray.ModeRequested += (_, mode) =>
        {
            ShowFromTray();
            _model.SetMode(this, mode);
        };
        _tray.AutostartToggled += (_, _) =>
        {
            var enable = !Autostart.IsEnabled;
            ShowMessage(Autostart.Set(enable)
                ? (enable ? "CrioFire will start when you sign in to Windows." : "CrioFire won't start with Windows any more.")
                : "Could not change the Windows startup setting.");
            RefreshPage();
        };
        _tray.ExitRequested += (_, _) => ExitApp();

        _model.RefreshCore();
        UpdateService();
        NavDashboard.IsChecked = true;
        _poll.Start();
        if (showWindow)
        {
            Show();
        }
        else
        {
            _pageTimer.Stop();
        }
    }

    /// <summary>Opens the window from the tray (or when the app is started a second time).</summary>
    internal void ShowFromTray()
    {
        if (!IsVisible)
        {
            Show();
        }

        if (WindowState == WindowState.Minimized)
        {
            WindowState = WindowState.Normal;
        }

        Activate();
        RefreshPage();
        if (_current?.AutoRefresh is { } every)
        {
            _pageTimer.Interval = every;
            _pageTimer.Start();
        }
    }

    /// <summary>Closes the app for good. The service keeps filtering.</summary>
    internal void ExitApp()
    {
        _exiting = true;
        Close();
        Application.Current.Shutdown();
    }

    /// <summary>Closing the window keeps CrioFire running in the tray, unless the user turned that off.</summary>
    private void OnClosing(object? sender, CancelEventArgs e)
    {
        if (_exiting || !Prefs.Current.CloseToTray)
        {
            _exiting = true;
            Dispatcher.BeginInvoke(() => Application.Current.Shutdown());
            return;
        }

        e.Cancel = true;
        Hide();
        _pageTimer.Stop();
        if (!Prefs.Current.TrayHintShown)
        {
            Prefs.Current.TrayHintShown = true;
            Prefs.Save();
            _tray?.ShowHint(
                "CrioFire is still protecting you",
                "It keeps running here, next to the clock. Click the icon to open it; right-click for options.");
        }
    }

    private void OnNav(object sender, RoutedEventArgs e)
    {
        if (sender is RadioButton { Content: string name })
        {
            Show(name);
        }
    }

    private void GoTo(string page)
    {
        var target = page switch
        {
            "Activity" => NavActivity,
            "Rules" => NavRules,
            "Connections" => NavConnections,
            "Reports" => NavReports,
            "Settings" => NavSettings,
            _ => NavDashboard,
        };
        target.IsChecked = true;
    }

    private void Show(string name)
    {
        if (!_pages.TryGetValue(name, out var page))
        {
            page = name switch
            {
                "Activity" => new ActivityPage(_model),
                "Rules" => new RulesPage(_model),
                "Connections" => new ConnectionsPage(_model),
                "Reports" => new ReportsPage(_model),
                "Settings" => new SettingsPage(_model),
                _ => (IPage)new DashboardPage(_model),
            };
            _pages[name] = page;
        }

        _current = page;
        PageHost.Content = page;
        PageActions.Content = page.Actions;
        _pageTimer.Stop();
        RefreshPage();
        if (page.AutoRefresh is { } every)
        {
            _pageTimer.Interval = every;
            _pageTimer.Start();
        }
    }

    private void RefreshPage()
    {
        if (_current is null)
        {
            return;
        }

        _current.Refresh();
        PageTitle.Text = _current.Title;
        PageSubtitle.Text = _current.Subtitle;
        UpdateService();
    }

    /// <summary>Every 2 seconds: service status, rules, and in Ask mode new programs to ask about.</summary>
    private void Poll()
    {
        var wasOnline = _model.Status is not null;
        var previousMode = _model.Mode;
        _model.RefreshCore();
        UpdateService();
        if (wasOnline != (_model.Status is not null) || previousMode != _model.Mode)
        {
            RefreshPage();
        }

        if (_model.Mode != "ask")
        {
            return;
        }

        var events = Service.Call(new ApiRequest { Op = ApiOps.Events, Minutes = 1 }, out _)?.Events;
        if (events is null)
        {
            return;
        }

        var alerts = _tracker.NewAlerts(events, _model.Rules);
        foreach (var alert in alerts)
        {
            RaiseAlert(alert);
        }

        if (alerts.Count > 0)
        {
            RefreshPage();
            UpdateService();
        }
    }

    private void RaiseAlert(EventInfo blocked)
    {
        var app = blocked.App!;
        _model.AddPending(blocked);
        var window = new AlertWindow(blocked);
        _alerts[app] = window;
        window.Closed += (_, _) =>
        {
            // Not in the map any more = decided on the dashboard; nothing left to do.
            if (!_alerts.Remove(app))
            {
                return;
            }

            switch (window.Choice)
            {
                case AlertChoice.Allow:
                    _model.SetRule(app, "allow");
                    _tracker.Decided(app);
                    break;
                case AlertChoice.AllowFor:
                    _model.SetRule(app, "allow", window.Minutes);
                    _tracker.Decided(app);
                    break;
                case AlertChoice.Block:
                    _model.SetRule(app, "block");
                    _tracker.Decided(app);
                    break;
                default:
                    _tracker.Dismissed(app);
                    break;
            }
        };
        window.Show();
    }

    /// <summary>A pending program was decided (on a page or in its alert): close the alert without acting twice.</summary>
    private void CloseAlert(string app)
    {
        _tracker.Decided(app);
        if (_alerts.Remove(app, out var window))
        {
            window.Close();
        }
    }

    private void UpdateService()
    {
        var status = _model.Status;
        _tray?.Update(status, _model.Mode, _model.Pending.Count);
        if (status is null)
        {
            ServiceText.Text = "Not running";
            ServiceDot.SetResourceReference(Shape.FillProperty, "FireBrush");
            ServiceDotGlow.Color = Color.FromRgb(0xFF, 0x4A, 0x32);
        }
        else
        {
            ServiceText.Text = status.Installed ? $"Running · {ShortVersion(status.Version)}" : "Running · not set up";
            ServiceDot.SetResourceReference(Shape.FillProperty, "IceBrush");
            ServiceDotGlow.Color = Color.FromRgb(0x7D, 0xD8, 0xFF);
        }
    }

    private static string ShortVersion(string version)
    {
        var plus = version.IndexOf('+', StringComparison.Ordinal);
        return "v" + (plus > 0 ? version[..plus] : version);
    }

    private void ShowMessage(string? text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return;
        }

        MessageText.Text = text;
        MessageBar.Visibility = Visibility.Visible;
        _messageTimer.Stop();
        _messageTimer.Start();
    }

    private void OnPanic(object sender, RoutedEventArgs e) => _model.Panic(this);

    private void OnToggleTheme(object sender, RoutedEventArgs e) => ThemeManager.Toggle();

    private void UpdateThemeButton()
    {
        var dark = ThemeManager.IsDark;
        ThemeButton.ToolTip = dark ? "Switch to light mode" : "Switch to dark mode";
        SunSpot.SetResourceReference(Border.BackgroundProperty, dark ? "TransparentBrush" : "SegOnBrush");
        MoonSpot.SetResourceReference(Border.BackgroundProperty, dark ? "SegOnBrush" : "TransparentBrush");
        SunIcon.Stroke = dark ? (Brush)FindResource("NavTextBrush") : new SolidColorBrush(Color.FromRgb(0xE0, 0x8A, 0x00));
        MoonIcon.Stroke = dark ? (Brush)FindResource("IceTextBrush") : (Brush)FindResource("NavTextBrush");
    }
}
