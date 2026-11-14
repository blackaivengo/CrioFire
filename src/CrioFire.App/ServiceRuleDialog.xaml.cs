using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using CrioFire.Core;

namespace CrioFire.App;

/// <summary>The service rule the user chose: service name, "block"/"allow", "out"/"in"/"both", and the networks it applies on.</summary>
internal sealed record ServiceRuleChoice(string Service, string Action, string Direction, NetworkProfiles Networks = NetworkProfiles.Any);

public sealed record ServiceRow(string Name, string DisplayName, string State, string Pid);

/// <summary>Picks one Windows service from the installed ones and makes an allow or block rule for it.</summary>
public partial class ServiceRuleDialog : Window
{
    private readonly List<ServiceRow> _all;

    public ServiceRuleDialog()
    {
        InitializeComponent();
        _all = WindowsServiceList.Read()
            .Select(s => new ServiceRow(s.Name, s.DisplayName, s.Running ? L.T("Running") : L.T("Stopped"), s.Running ? s.ProcessId.ToString(System.Globalization.CultureInfo.CurrentCulture) : string.Empty))
            .ToList();
        Table.ItemsSource = _all;
        MouseLeftButtonDown += (_, e) =>
        {
            // Drag the window by its background, not from the list, the filter or the buttons.
            if (e.ButtonState == MouseButtonState.Pressed && !Table.IsMouseOver && !FilterBox.IsMouseOver && e.OriginalSource is not Button)
            {
                DragMove();
            }
        };
        Loaded += (_, _) =>
        {
            FilterBox.Focus();
            Update();
        };
    }

    internal ServiceRuleChoice? Result { get; private set; }

    /// <summary>Opens the dialog, optionally with a service selected and an action chosen.</summary>
    internal static ServiceRuleChoice? Ask(Window owner, string? service = null, string action = "block")
    {
        var dialog = new ServiceRuleDialog { Owner = owner };
        dialog.ActionAllow.IsChecked = action == "allow";
        dialog.ActionBlock.IsChecked = action != "allow";
        if (service is not null)
        {
            if (dialog._all.FirstOrDefault(s => string.Equals(s.Name, service, StringComparison.OrdinalIgnoreCase)) is { } row)
            {
                dialog.Table.SelectedItem = row;
                dialog.Table.ScrollIntoView(row);
            }
        }

        return dialog.ShowDialog() == true ? dialog.Result : null;
    }

    private void OnFilter(object sender, TextChangedEventArgs e)
    {
        var text = FilterBox.Text.Trim();
        var selected = Table.SelectedItem;
        Table.ItemsSource = text.Length == 0
            ? _all
            : _all.Where(s => s.Name.Contains(text, StringComparison.OrdinalIgnoreCase) || s.DisplayName.Contains(text, StringComparison.OrdinalIgnoreCase)).ToList();
        Table.SelectedItem = selected;
        Update();
    }

    private void OnChanged(object sender, RoutedEventArgs e) => Update();

    private void OnDoubleClick(object sender, MouseButtonEventArgs e)
    {
        if (Table.SelectedItem is ServiceRow)
        {
            OnSave(sender, e);
        }
    }

    private string Direction => DirIn.IsChecked == true ? "in" : DirBoth.IsChecked == true ? "both" : "out";

    private NetworkProfiles Networks => NetHomeWork.IsChecked == true ? NetworkProfiles.Domain | NetworkProfiles.Private
        : NetPublic.IsChecked == true ? NetworkProfiles.Public : NetworkProfiles.Any;

    private void Update()
    {
        if (!IsLoaded)
        {
            return;
        }

        var allow = ActionAllow.IsChecked == true;
        SaveButton.SetResourceReference(StyleProperty, allow ? "IceButton" : "FireButton");
        if (Table.SelectedItem is not ServiceRow row)
        {
            SaveButton.IsEnabled = false;
            PreviewText.Text = L.T("Choose a service.");
            return;
        }

        SaveButton.IsEnabled = true;
        var direction = Direction switch
        {
            "in" => L.T("when others connect to it"),
            "both" => L.T("in both directions"),
            _ => L.T("when it connects out"),
        };
        var where = Networks == NetworkProfiles.Any ? string.Empty : L.T($" on {NetworkScope.Label(Networks)} (elsewhere the mode decides)");
        PreviewText.Text = L.T($"{row.DisplayName} ({row.Name}) {(allow ? "is allowed" : "is blocked")} {direction}{where}, whichever process runs it.");
        PreviewBox.SetResourceReference(BackgroundProperty, allow ? "ChipIceBrush" : "ChipFireBrush");
        PreviewText.SetResourceReference(ForegroundProperty, allow ? "ChipIceTextBrush" : "ChipFireTextBrush");
    }

    private void OnSave(object sender, RoutedEventArgs e)
    {
        if (Table.SelectedItem is ServiceRow row)
        {
            Result = new ServiceRuleChoice(row.Name, ActionAllow.IsChecked == true ? "allow" : "block", Direction, Networks);
            DialogResult = true;
        }
    }
}
