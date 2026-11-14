using System.Windows;
using System.Windows.Automation;
using System.Windows.Automation.Peers;
using System.Windows.Automation.Provider;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Input;
using System.Windows.Media;

namespace CrioFire.App;

/// <summary>Says something through the screen reader (Narrator, NVDA, JAWS) without moving the focus.</summary>
internal static class ScreenReader
{
    /// <param name="important">Interrupts what the screen reader is saying (alerts, panic), instead of waiting.</param>
    public static void Say(DependencyObject? source, string? text, bool important = false)
    {
        if (string.IsNullOrWhiteSpace(text) || source is null)
        {
            return;
        }

        var window = source as Window ?? Window.GetWindow(source);
        if (window is null)
        {
            return;
        }

        var peer = UIElementAutomationPeer.FromElement(window) ?? UIElementAutomationPeer.CreatePeerForElement(window);
        peer?.RaiseNotificationEvent(
            AutomationNotificationKind.Other,
            important ? AutomationNotificationProcessing.ImportantMostRecent : AutomationNotificationProcessing.MostRecent,
            text,
            important ? "CrioFire.Important" : "CrioFire.Message");
    }
}

/// <summary>
/// Text only screen readers see, such as what a chart shows: a tiny empty element they read as
/// text. Set the text with <see cref="AutomationProperties.NameProperty"/>.
/// </summary>
public sealed class SpokenText : FrameworkElement
{
    public SpokenText()
    {
        Width = 1;
        Height = 1;
        Focusable = false;
        IsHitTestVisible = false;
    }

    protected override AutomationPeer OnCreateAutomationPeer() => new SpokenTextAutomationPeer(this);

    private sealed class SpokenTextAutomationPeer(SpokenText owner) : FrameworkElementAutomationPeer(owner)
    {
        protected override AutomationControlType GetAutomationControlTypeCore() => AutomationControlType.Text;

        protected override string GetClassNameCore() => nameof(SpokenText);
    }
}

/// <summary>
/// A panel that opens something when clicked, like the Dashboard's cards: with the mouse, with
/// Enter or Space when it has the keyboard focus, and from screen readers, which see a button named
/// after its tooltip. Clicks on a control inside it (a button, a switch) are that control's.
/// </summary>
public sealed class ClickableCard : ContentControl
{
    public static readonly RoutedEvent ClickEvent =
        EventManager.RegisterRoutedEvent(nameof(Click), RoutingStrategy.Direct, typeof(RoutedEventHandler), typeof(ClickableCard));

    public ClickableCard()
    {
        // Local values, so they win over the card styles (which make panels unfocusable).
        Focusable = true;
        Cursor = Cursors.Hand;
        SetResourceReference(FocusVisualStyleProperty, "FocusRing");
    }

    public event RoutedEventHandler Click
    {
        add => AddHandler(ClickEvent, value);
        remove => RemoveHandler(ClickEvent, value);
    }

    internal void PerformClick() => RaiseEvent(new RoutedEventArgs(ClickEvent, this));

    protected override void OnMouseLeftButtonUp(MouseButtonEventArgs e)
    {
        base.OnMouseLeftButtonUp(e);
        if (!e.Handled && !FromInnerControl(e.OriginalSource as DependencyObject))
        {
            e.Handled = true;
            PerformClick();
        }
    }

    protected override void OnKeyDown(KeyEventArgs e)
    {
        base.OnKeyDown(e);
        if (!e.Handled && ReferenceEquals(e.OriginalSource, this) && e.Key is Key.Enter or Key.Space)
        {
            e.Handled = true;
            PerformClick();
        }
    }

    protected override AutomationPeer OnCreateAutomationPeer() => new ClickableCardAutomationPeer(this);

    /// <summary>True when the click landed on a button, switch, field or another card inside this one.</summary>
    private bool FromInnerControl(DependencyObject? source)
    {
        for (var node = source; node is not null && !ReferenceEquals(node, this); node = ParentOf(node))
        {
            if (node is ButtonBase or TextBoxBase or Selector or ClickableCard or ScrollBar)
            {
                return true;
            }
        }

        return false;
    }

    private static DependencyObject? ParentOf(DependencyObject node) =>
        node is Visual or System.Windows.Media.Media3D.Visual3D ? VisualTreeHelper.GetParent(node) : LogicalTreeHelper.GetParent(node);

    private sealed class ClickableCardAutomationPeer(ClickableCard owner) : FrameworkElementAutomationPeer(owner), IInvokeProvider
    {
        protected override AutomationControlType GetAutomationControlTypeCore() => AutomationControlType.Button;

        protected override string GetClassNameCore() => nameof(ClickableCard);

        protected override string GetNameCore()
        {
            var name = base.GetNameCore();
            return string.IsNullOrEmpty(name) && Owner is FrameworkElement { ToolTip: string tip } ? tip : name;
        }

        public override object GetPattern(PatternInterface patternInterface) =>
            patternInterface == PatternInterface.Invoke ? this : base.GetPattern(patternInterface);

        public void Invoke()
        {
            if (!IsEnabled())
            {
                throw new ElementNotEnabledException();
            }

            ((ClickableCard)Owner).PerformClick();
        }
    }
}
