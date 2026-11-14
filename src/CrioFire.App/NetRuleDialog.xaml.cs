using System.IO;
using System.Windows;
using System.Windows.Input;
using CrioFire.Core;
using Microsoft.Win32;

namespace CrioFire.App;

/// <summary>Creates a rule by port and/or remote address, optionally for one program.</summary>
public partial class NetRuleDialog : Window
{
    public NetRuleDialog()
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
            PortsBox.Focus();
            Update();
        };
    }

    /// <summary>The rule to add, once the user pressed "Add rule".</summary>
    public NetRule? Result { get; private set; }

    /// <summary>Opens the dialog, optionally for one program; returns the rule or null.</summary>
    internal static NetRule? Ask(Window owner, string? appPath = null)
    {
        var dialog = new NetRuleDialog { Owner = owner };
        if (appPath is not null)
        {
            dialog.AppBox.Text = appPath;
        }

        return dialog.ShowDialog() == true ? dialog.Result : null;
    }

    private void OnChanged(object sender, RoutedEventArgs e) => Update();

    private NetRule? Build(out string? error) => NetRule.Create(
        ActionAllow.IsChecked == true ? RuleAction.Allow : RuleAction.Block,
        DirIn.IsChecked == true ? TrafficDirection.Inbound : DirBoth.IsChecked == true ? TrafficDirection.Both : TrafficDirection.Outbound,
        ProtoTcp.IsChecked == true ? NetProtocol.Tcp : ProtoUdp.IsChecked == true ? NetProtocol.Udp : NetProtocol.Any,
        PortsBox.Text,
        AddressesBox.Text,
        string.IsNullOrWhiteSpace(AppBox.Text) ? null : AppBox.Text.Trim().Trim('"'),
        out error,
        NetHomeWork.IsChecked == true ? NetworkProfiles.Domain | NetworkProfiles.Private
            : NetPublic.IsChecked == true ? NetworkProfiles.Public : NetworkProfiles.Any);

    /// <summary>Explains the rule in words as it is typed, or what is wrong with it.</summary>
    private void Update()
    {
        if (!IsLoaded)
        {
            return;
        }

        PortsHint.Text = DirIn.IsChecked == true
            ? L.T("Ports on this PC that others connect to, e.g. 445 or 3389. Leave empty for any.")
            : DirBoth.IsChecked == true
                ? L.T("Remote ports outbound, local ports inbound, e.g. 80, 443 or 8000-8100. Leave empty for any.")
                : L.T("Ports on the remote side, e.g. 80, 443 or 8000-8100. Leave empty for any.");

        var rule = Build(out var error);
        var appMissing = rule?.AppPath is { } app && !File.Exists(app);
        SaveButton.IsEnabled = rule is not null && !appMissing;
        SaveButton.SetResourceReference(StyleProperty, ActionAllow.IsChecked == true ? "IceButton" : "FireButton");
        if (rule is null || appMissing)
        {
            PreviewText.Text = appMissing ? L.T("There is no program at that path.") : error ?? string.Empty;
            PreviewBox.SetResourceReference(BackgroundProperty, "ChipFireBrush");
            PreviewText.SetResourceReference(ForegroundProperty, "ChipFireTextBrush");
            return;
        }

        var who = rule.AppPath is null ? L.T("Every program") : Path.GetFileName(rule.AppPath);
        var verb = rule.Action == RuleAction.Block ? L.T("is blocked") : L.T("is allowed");
        var direction = rule.Direction switch
        {
            TrafficDirection.Inbound => L.T("when others connect to it"),
            TrafficDirection.Both => L.T("in both directions"),
            _ => L.T("when it connects out"),
        };
        var conditions = new List<string>();
        if (rule.Protocol != NetProtocol.Any)
        {
            conditions.Add(rule.Protocol.ToString().ToUpperInvariant());
        }

        if (rule.Ports.Length > 0)
        {
            conditions.Add((rule.Direction == TrafficDirection.Inbound ? L.T("local port ") : "port ") + rule.Ports);
        }

        if (rule.Addresses.Length > 0)
        {
            conditions.Add(rule.Addresses);
        }

        var where = rule.Networks == NetworkProfiles.Any ? string.Empty : $" on {NetworkScope.Label(rule.Networks)}";
        PreviewText.Text = $"{who} {verb} {direction}{where}" + (conditions.Count > 0 ? $": {string.Join(" · ", conditions)}." : ".");
        PreviewBox.SetResourceReference(BackgroundProperty, rule.Action == RuleAction.Block ? "ChipFireBrush" : "ChipIceBrush");
        PreviewText.SetResourceReference(ForegroundProperty, rule.Action == RuleAction.Block ? "ChipFireTextBrush" : "ChipIceTextBrush");
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
        Result = Build(out _);
        if (Result is not null)
        {
            DialogResult = true;
        }
    }
}
