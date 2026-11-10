using System.Windows;

namespace CrioFire.App;

/// <summary>criofire-ui.exe: the CrioFire desktop app.</summary>
public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        ThemeManager.Initialize();
        var window = new MainWindow();
        MainWindow = window;
        window.Show();
    }
}
