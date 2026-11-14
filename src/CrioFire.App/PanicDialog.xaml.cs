using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using CrioFire.Core;

namespace CrioFire.App;

/// <summary>
/// The panic choices: allow everything (rules paused), block all network traffic, or remove every
/// rule. The first two keep the rules, so one click on "Resume my rules" undoes them.
/// </summary>
public partial class PanicDialog : Window
{
    private string? _action;

    private PanicDialog(string current)
    {
        InitializeComponent();
        IntroText.Text = current switch
        {
            "allow" => L.T("Panic is on: every connection is allowed and your rules are paused. They are all still there."),
            "block" => L.T("Panic is on: all network traffic is blocked. Your rules are all still there."),
            _ => L.T("Something can't connect, or something is connecting that shouldn't? Pick what to do. The first two keep every rule you made, and one click on Resume brings them back."),
        };

        if (current != "off")
        {
            Add("off", L.T("Resume my rules"), L.T("End panic. Your rules and mode apply again, exactly as before."), "IceButton");
        }

        if (current != "allow")
        {
            Add("allow", L.T("Allow everything, pause my rules"),
                L.T("Every program may connect, in and out. Nothing is deleted: your rules, mode and automatic rules wait until you resume."),
                current == "off" ? "IceButton" : "OutlineIceButton");
        }

        if (current != "block")
        {
            Add("block", L.T("Block all network traffic"),
                L.T("Like pulling the network cable: no new connection in or out, whatever the rules say. Programs on this PC can still talk to each other. Your rules are kept."),
                "OutlineFireButton");
        }

        Add("remove", L.T("Remove all rules"),
            L.T("Deletes every rule you made and goes back to Learning mode. This cannot be undone."),
            "GhostButton");

        MouseLeftButtonDown += (_, e) =>
        {
            if (e.ButtonState == MouseButtonState.Pressed && e.OriginalSource is not Button)
            {
                DragMove();
            }
        };
    }

    /// <summary>
    /// Shows the choices for the current panic state (off, allow, block). Returns the action for the
    /// panic API (off, allow, block, remove), or null when cancelled.
    /// </summary>
    public static string? Ask(Window owner, string current)
    {
        var dialog = new PanicDialog(current) { Owner = owner };
        dialog.ShowDialog();
        return dialog._action;
    }

    private void Add(string action, string title, string description, string style)
    {
        var text = new StackPanel { Width = 440 };
        text.Children.Add(new TextBlock { Text = title, FontSize = 14, FontWeight = FontWeights.SemiBold, TextWrapping = TextWrapping.Wrap });
        text.Children.Add(new TextBlock
        {
            Text = description,
            FontSize = 12,
            FontWeight = FontWeights.Normal,
            Opacity = 0.82,
            TextWrapping = TextWrapping.Wrap,
            Margin = new Thickness(0, 3, 0, 0),
        });

        var button = new Button
        {
            Content = text,
            Style = (Style)FindResource(style),
            Padding = new Thickness(18, 12, 18, 12),
            Margin = new Thickness(0, 0, 0, 10),
            HorizontalAlignment = HorizontalAlignment.Stretch,
        };
        button.Click += (_, _) =>
        {
            _action = action;
            Close();
        };
        Options.Children.Add(button);
    }
}
