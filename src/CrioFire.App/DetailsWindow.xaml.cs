using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using CrioFire.Core;

namespace CrioFire.App;

/// <summary>"More info" from a row's right-click menu: everything known about it, with allow and block.</summary>
public partial class DetailsWindow : Window
{
    private readonly AppModel _model;
    private readonly MenuTarget _target;

    private DetailsWindow(AppModel model, MenuTarget target)
    {
        _model = model;
        _target = target;
        InitializeComponent();
        TitleText.Text = target.Item is { } i ? $"{target.Who} · {(i.Allowed ? "allowed" : "blocked")}" : target.Who;
        PathText.Text = target.App ?? (target.Remote is { } r ? NetworkFacts.AddressScope(r) : string.Empty);
        AllowButton.Content = target.Item is { Allowed: false } ? L.T("Unblock") : L.T("Allow");
        AllowButton.Visibility = BlockButton.Visibility = target.App is null ? Visibility.Collapsed : Visibility.Visible;
        FolderButton.IsEnabled = target.App is not null && File.Exists(target.App);
        ShowFacts();
        MouseLeftButtonDown += (_, e) =>
        {
            if (e.ButtonState == MouseButtonState.Pressed && e.OriginalSource is not Button)
            {
                DragMove();
            }
        };
        Loaded += async (_, _) =>
        {
            if (ConnectionFacts.NeedsLookup(target.Remote))
            {
                await ConnectionFacts.LookUpAsync(target.Remote!);
                ShowFacts();
            }
        };
    }

    internal static void Open(Window owner, AppModel model, MenuTarget target) =>
        new DetailsWindow(model, target) { Owner = owner }.ShowDialog();

    private void ShowFacts() => Facts.ItemsSource = ConnectionFacts.For(_target, _model);

    private void OnAllow(object sender, RoutedEventArgs e) => Act("allow");

    private void OnBlock(object sender, RoutedEventArgs e) => Act("block");

    private void Act(string action)
    {
        var owner = Owner;
        Close();
        _model.ApplyToMany(owner, [_target.AsItem()], action);
    }

    private void OnFolder(object sender, RoutedEventArgs e) => RowMenu.OpenFolder(_target.App);

    private void OnCopy(object sender, RoutedEventArgs e) =>
        RowMenu.Copy(_model, ConnectionFacts.AsText(_target.Who, _target.App, ConnectionFacts.For(_target, _model)));
}
