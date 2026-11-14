using System.IO;
using System.Windows;
using System.Windows.Input;
using CrioFire.Core;
using Microsoft.Win32;

namespace CrioFire.App;

/// <summary>The domain rule the user chose.</summary>
internal sealed record DomainRuleChoice(string Domain, string Action, string? App, NetworkProfiles Networks);

/// <summary>Creates a rule for a domain and every name under it, optionally for one program.</summary>
public partial class DomainRuleDialog : Window
{
    public DomainRuleDialog()
    {
        InitializeComponent();
        MouseLeftButtonDown += (_, e) =>
        {
            if (e.ButtonState == MouseButtonState.Pressed && e.OriginalSource is not System.Windows.Controls.TextBox)
            {
                DragMove();
            }
        };
        Loaded += (_, _) =>
        {
            DomainBox.Focus();
            Update();
        };
    }

    internal DomainRuleChoice? Result { get; private set; }

    internal static DomainRuleChoice? Ask(Window owner, string? domain = null)
    {
        var dialog = new DomainRuleDialog { Owner = owner };
        if (domain is not null)
        {
            dialog.DomainBox.Text = domain;
        }

        return dialog.ShowDialog() == true ? dialog.Result : null;
    }

    private void OnChanged(object sender, RoutedEventArgs e) => Update();

    private NetworkProfiles Networks => NetHomeWork.IsChecked == true ? NetworkProfiles.Domain | NetworkProfiles.Private
        : NetPublic.IsChecked == true ? NetworkProfiles.Public : NetworkProfiles.Any;

    private string? App => string.IsNullOrWhiteSpace(AppBox.Text) ? null : AppBox.Text.Trim().Trim('"');

    private void Update()
    {
        if (!IsLoaded)
        {
            return;
        }

        var allow = ActionAllow.IsChecked == true;
        var domain = DomainNames.Normalize(DomainBox.Text, out var error);
        var appMissing = App is { } app && !File.Exists(app);
        SaveButton.IsEnabled = domain is not null && !appMissing;
        SaveButton.SetResourceReference(StyleProperty, allow ? "IceButton" : "FireButton");
        if (domain is null || appMissing)
        {
            PreviewText.Text = string.IsNullOrWhiteSpace(DomainBox.Text) ? L.T("Type a domain, e.g. example.com.") : appMissing ? L.T("There is no program at that path.") : error ?? string.Empty;
            PreviewBox.SetResourceReference(BackgroundProperty, "ChipFireBrush");
            PreviewText.SetResourceReference(ForegroundProperty, "ChipFireTextBrush");
            return;
        }

        var who = App is null ? L.T("Every program") : Path.GetFileName(App);
        var where = Networks == NetworkProfiles.Any ? string.Empty : $" on {NetworkScope.Label(Networks)}";
        PreviewText.Text = L.T($"{who} {(allow ? L.T("may connect") : L.T("is blocked from connecting"))} to {domain} and every name under it{where}.");
        PreviewBox.SetResourceReference(BackgroundProperty, allow ? "ChipIceBrush" : "ChipFireBrush");
        PreviewText.SetResourceReference(ForegroundProperty, allow ? "ChipIceTextBrush" : "ChipFireTextBrush");
    }

    private void OnBrowse(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog { Filter = "Programs (*.exe)|*.exe", Title = L.T("Choose the program this rule is for") };
        if (dialog.ShowDialog(this) == true)
        {
            AppBox.Text = dialog.FileName;
        }
    }

    private void OnSave(object sender, RoutedEventArgs e)
    {
        if (DomainNames.Normalize(DomainBox.Text, out _) is { } domain && !(App is { } app && !File.Exists(app)))
        {
            Result = new DomainRuleChoice(domain, ActionAllow.IsChecked == true ? "allow" : "block", App, Networks);
            DialogResult = true;
        }
    }
}
