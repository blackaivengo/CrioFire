using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;

namespace CrioFire.App;

/// <summary>A themed question with a few answers, in place of the system message box.</summary>
public partial class ChoiceDialog : Window
{
    private int? _choice;

    private ChoiceDialog(string title, string message, IReadOnlyList<string> choices, int defaultIndex, bool danger)
    {
        InitializeComponent();
        Title = title;
        TitleText.Text = title;
        MessageText.Text = message;
        if (danger)
        {
            Glow.SetResourceReference(Border.BackgroundProperty, "FireGlowBrush");
        }

        for (var i = 0; i < choices.Count; i++)
        {
            var index = i;
            var styleKey = i == defaultIndex ? (danger ? "FireButton" : "IceButton") : (i == choices.Count - 1 ? "GhostButton" : "OutlineIceButton");
            var button = new Button
            {
                Content = choices[i],
                Style = (Style)FindResource(styleKey),
                Margin = new Thickness(8, 4, 0, 0),
                IsDefault = i == defaultIndex,
            };
            button.Click += (_, _) =>
            {
                _choice = index;
                Close();
            };
            Buttons.Children.Add(button);
        }

        FitButtonsInOneRow();

        MouseLeftButtonDown += (_, e) =>
        {
            if (e.ButtonState == MouseButtonState.Pressed)
            {
                DragMove();
            }
        };
        KeyDown += (_, e) =>
        {
            if (e.Key == Key.Escape)
            {
                Close();
            }
        };
    }

    /// <summary>
    /// Widens the dialog so every answer fits on one row (500 px at least). Only if that would not
    /// fit on the screen do the answers stack, one per row, full width.
    /// </summary>
    private void FitButtonsInOneRow()
    {
        Buttons.Measure(new Size(double.PositiveInfinity, double.PositiveInfinity));
        const double chrome = (28 * 2) + (26 * 2) + 2;   // window margin, card padding, card border
        var needed = Math.Ceiling(Buttons.DesiredSize.Width + chrome);
        var screen = SystemParameters.WorkArea.Width * 0.9;
        if (needed <= screen)
        {
            Width = Math.Max(Width, needed);
            return;
        }

        Buttons.Orientation = Orientation.Vertical;
        Buttons.HorizontalAlignment = HorizontalAlignment.Stretch;
        foreach (var child in Buttons.Children.OfType<Button>())
        {
            child.HorizontalAlignment = HorizontalAlignment.Stretch;
        }
    }

    /// <summary>Returns the index of the chosen answer, or null if the dialog was closed with Escape.</summary>
    public static int? Ask(Window owner, string title, string message, IReadOnlyList<string> choices, int defaultIndex = 0, bool danger = false)
    {
        var dialog = new ChoiceDialog(title, message, choices, defaultIndex, danger) { Owner = owner };
        dialog.ShowDialog();
        return dialog._choice;
    }
}
