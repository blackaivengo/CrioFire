using System.Windows;
using CrioFire.Core;

namespace CrioFire.App;

/// <summary>
/// criofire-ui.exe: the CrioFire desktop app. One copy runs per user; starting it again brings
/// that copy forward. With --tray (how Windows starts it at sign-in) it starts in the
/// notification area without opening the window.
/// </summary>
public partial class App : Application
{
    private SingleInstance? _instance;

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        _instance = new SingleInstance();
        if (!_instance.IsFirst)
        {
            _instance.SignalFirst();
            _instance.Dispose();
            _instance = null;
            Shutdown();
            return;
        }

        ThemeManager.Initialize();
        var window = new MainWindow();
        MainWindow = window;
        _instance.OnShowRequested(() => Dispatcher.BeginInvoke(() => window.ShowFromTray()));
        var inTray = e.Args.Any(a => string.Equals(a, AutostartCommand.TrayArgument, StringComparison.OrdinalIgnoreCase));
        window.Start(showWindow: !inTray);
    }

    protected override void OnExit(ExitEventArgs e)
    {
        _instance?.Dispose();
        base.OnExit(e);
    }
}
