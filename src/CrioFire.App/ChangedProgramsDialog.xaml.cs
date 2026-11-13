using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using CrioFire.Core;

namespace CrioFire.App;

/// <summary>
/// Lists the allowed programs whose file changed since the user allowed them, with what changed,
/// and lets the user allow each one again, block it, or look at the file first.
/// </summary>
public partial class ChangedProgramsDialog : Window
{
    private readonly AppModel _model;

    private ChangedProgramsDialog(AppModel model, IReadOnlyList<ChangedProgram> programs)
    {
        _model = model;
        InitializeComponent();
        foreach (var program in programs.OrderByDescending(p => p.DetectedUtc))
        {
            ProgramList.Children.Add(Card(program));
        }

        MouseLeftButtonDown += (_, e) =>
        {
            if (e.ButtonState == MouseButtonState.Pressed && e.OriginalSource is not Button)
            {
                DragMove();
            }
        };
    }

    internal static void Review(Window owner, AppModel model)
    {
        var programs = AppModel.ChangedPrograms();
        if (programs.Count == 0)
        {
            model.Say("Every allowed program is still the file you allowed.");
            return;
        }

        new ChangedProgramsDialog(model, programs) { Owner = owner }.ShowDialog();
    }

    private Border Card(ChangedProgram program)
    {
        var body = new StackPanel();
        body.Children.Add(new TextBlock
        {
            Text = KnownApps.DisplayName(program.App),
            FontSize = 15,
            FontWeight = FontWeights.SemiBold,
            TextWrapping = TextWrapping.Wrap,
        });
        body.Children.Add(Muted(string.Join("\n", TextWrap.Path(program.App, 90))));
        body.Children.Add(Line($"Publisher when you allowed it: {program.WasPublisher ?? "unsigned"}"));
        body.Children.Add(Line($"Publisher now: {program.NowPublisher ?? "unsigned"}"));
        body.Children.Add(Line(program.WasPublisher is null && program.NowPublisher is null
            ? "The contents of this unsigned program are different."
            : program.NowPublisher is null
                ? "The file is no longer signed."
                : "Another publisher signed this file."));
        body.Children.Add(Muted(program.Blocked
            ? $"Noticed {program.DetectedUtc.ToLocalTime():g}. Blocked until you decide."
            : $"Noticed {program.DetectedUtc.ToLocalTime():g}. Not blocked: in Learning mode programs without a rule may connect."));

        var buttons = new WrapPanel { Margin = new Thickness(0, 12, 0, 0) };
        var card = new Border
        {
            CornerRadius = new CornerRadius(12),
            BorderThickness = new Thickness(1),
            Padding = new Thickness(18, 14, 18, 12),
            Margin = new Thickness(0, 0, 0, 12),
            Child = new StackPanel { Children = { body, buttons } },
        };
        card.SetResourceReference(Border.BorderBrushProperty, "CardBorderBrush");
        card.SetResourceReference(Border.BackgroundProperty, "InsetBrush");

        buttons.Children.Add(MakeButton("Allow again", "OutlineIceButton", () => Done(card, _model.TrustChanged(program))));
        buttons.Children.Add(MakeButton(program.Blocked ? "Keep it blocked" : "Block it", "FireButton", () => Done(card, _model.BlockChanged(program))));
        if (File.Exists(program.App))
        {
            buttons.Children.Add(MakeButton("Open file location", "GhostButton", () => RowMenu.OpenFolder(program.App)));
        }

        return card;
    }

    private void Done(Border card, bool ok)
    {
        if (!ok)
        {
            return;
        }

        ProgramList.Children.Remove(card);
        if (ProgramList.Children.Count == 0)
        {
            Close();
        }
    }

    private Button MakeButton(string text, string style, Action click)
    {
        var button = new Button
        {
            Content = text,
            Style = (Style)FindResource(style),
            Margin = new Thickness(0, 0, 10, 0),
            MinHeight = 34,
        };
        button.Click += (_, _) => click();
        return button;
    }

    private static TextBlock Line(string text) => new()
    {
        Text = text,
        FontSize = 13,
        TextWrapping = TextWrapping.Wrap,
        Margin = new Thickness(0, 4, 0, 0),
    };

    private static TextBlock Muted(string text)
    {
        var block = new TextBlock
        {
            Text = text,
            FontSize = 12,
            TextWrapping = TextWrapping.Wrap,
            Margin = new Thickness(0, 4, 0, 0),
        };
        block.SetResourceReference(TextBlock.ForegroundProperty, "Text2Brush");
        return block;
    }
}
