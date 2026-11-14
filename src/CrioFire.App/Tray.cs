using System.Runtime.InteropServices;
using System.Windows;
using CrioFire.Core;
using CrioFire.Core.Api;
using Microsoft.Win32;
using Drawing = System.Drawing;
using DrawingImaging = System.Drawing.Imaging;
using Forms = System.Windows.Forms;

namespace CrioFire.App;

/// <summary>Per-user app preferences, loaded once.</summary>
internal static class Prefs
{
    public static UiPreferences Current { get; } = UiPreferences.Load();

    public static void Save() => Current.Save();
}

/// <summary>
/// Start the app quietly in the tray when the user signs in. The installer may add a machine-wide
/// entry (HKLM Run, with --machine) for everyone; a user turns that off for themselves with a
/// preference. Otherwise the user's own entry (HKCU Run) is used.
/// </summary>
internal static class Autostart
{
    private static string ExePath => Environment.ProcessPath ?? string.Empty;

    public static bool MachineEntryExists => Points(Registry.LocalMachine);

    public static bool IsEnabled => Points(Registry.CurrentUser) || (MachineEntryExists && !Prefs.Current.AutostartOff);

    public static bool Set(bool enabled)
    {
        try
        {
            var machine = MachineEntryExists;
            Prefs.Current.AutostartOff = !enabled && machine;
            Prefs.Save();
            using var key = Registry.CurrentUser.CreateSubKey(AutostartCommand.RunKey);
            if (enabled && !machine)
            {
                key.SetValue(AutostartCommand.ValueName, AutostartCommand.For(ExePath));
            }
            else
            {
                key.DeleteValue(AutostartCommand.ValueName, throwOnMissingValue: false);
            }

            return true;
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException or System.IO.IOException)
        {
            return false;
        }
    }

    private static bool Points(RegistryKey hive)
    {
        using var key = hive.OpenSubKey(AutostartCommand.RunKey);
        return AutostartCommand.Points(key?.GetValue(AutostartCommand.ValueName) as string, ExePath);
    }
}

/// <summary>One copy of the app per user session; starting it again brings the first one forward.</summary>
internal sealed class SingleInstance : IDisposable
{
    private readonly Mutex _mutex;
    private readonly EventWaitHandle _show;
    private RegisteredWaitHandle? _wait;

    public SingleInstance()
    {
        _mutex = new Mutex(initiallyOwned: true, @"Local\CrioFire.Ui", out var created);
        IsFirst = created;
        _show = new EventWaitHandle(false, EventResetMode.AutoReset, @"Local\CrioFire.Ui.Show");
    }

    public bool IsFirst { get; }

    public void SignalFirst() => _show.Set();

    public void OnShowRequested(Action action) =>
        _wait = ThreadPool.RegisterWaitForSingleObject(_show, (_, _) => action(), null, Timeout.Infinite, executeOnlyOnce: false);

    public void Dispose()
    {
        _wait?.Unregister(null);
        if (IsFirst)
        {
            _mutex.ReleaseMutex();
        }

        _mutex.Dispose();
        _show.Dispose();
    }
}

/// <summary>
/// The CrioFire icon in the notification area: shows whether you are protected (gray when the
/// service is down, a fire-red dot when programs wait for a decision) and offers a quick menu.
/// </summary>
internal sealed partial class TrayIcon : IDisposable
{
    private enum State
    {
        Normal,
        Pending,
        Offline,
    }

    private readonly Forms.NotifyIcon _icon = new();
    private readonly Forms.ContextMenuStrip _menu = new() { ShowImageMargin = false, ShowCheckMargin = true };
    private readonly Forms.ToolStripMenuItem _open = new(L.T("Open CrioFire"));
    private readonly Forms.ToolStripMenuItem _learning = new(L.T("Learning mode"));
    private readonly Forms.ToolStripMenuItem _ask = new(L.T("Ask mode"));
    private readonly Forms.ToolStripMenuItem _allowList = new(L.T("Allow-list mode"));
    private readonly Forms.ToolStripMenuItem _resume = new(L.T("Panic is on: resume my rules")) { Visible = false };
    private readonly Forms.ToolStripMenuItem _autostart = new(L.T("Start with Windows"));
    private readonly Forms.ToolStripMenuItem _exit = new(L.T("Exit (protection stays on)"));
    private readonly Drawing.Icon _base;
    private readonly Dictionary<State, Drawing.Icon> _icons = [];
    private State? _state;

    public TrayIcon()
    {
        using (var stream = Application.GetResourceStream(new Uri("pack://application:,,,/Assets/criofire.ico")).Stream)
        {
            _base = new Drawing.Icon(stream, Forms.SystemInformation.SmallIconSize);
        }

        _open.Font = new Drawing.Font(_menu.Font, Drawing.FontStyle.Bold);
        _open.Click += (_, _) => OpenRequested?.Invoke(this, EventArgs.Empty);
        _learning.Click += (_, _) => ModeRequested?.Invoke(this, "learning");
        _ask.Click += (_, _) => ModeRequested?.Invoke(this, "ask");
        _allowList.Click += (_, _) => ModeRequested?.Invoke(this, "allowlist");
        _autostart.Click += (_, _) => AutostartToggled?.Invoke(this, EventArgs.Empty);
        _resume.Click += (_, _) => ResumeRequested?.Invoke(this, EventArgs.Empty);
        _exit.Click += (_, _) => ExitRequested?.Invoke(this, EventArgs.Empty);
        _exit.ToolTipText = L.T("Closes the app. The CrioFire service keeps filtering connections.");
        _menu.Items.AddRange(new Forms.ToolStripItem[]
        {
            _open, _resume, new Forms.ToolStripSeparator(),
            _learning, _ask, _allowList, new Forms.ToolStripSeparator(),
            _autostart, new Forms.ToolStripSeparator(),
            _exit,
        });
        _menu.Opening += (_, _) => _autostart.Checked = Autostart.IsEnabled;
        ApplyTheme();
        ThemeManager.Changed += OnThemeChanged;

        _icon.ContextMenuStrip = _menu;
        _icon.MouseClick += (_, e) =>
        {
            if (e.Button == Forms.MouseButtons.Left)
            {
                OpenRequested?.Invoke(this, EventArgs.Empty);
            }
        };
        _icon.BalloonTipClicked += (_, _) => OpenRequested?.Invoke(this, EventArgs.Empty);
        Update(null, "learning", 0);
        _icon.Visible = true;
    }

    public event EventHandler? OpenRequested;

    public event EventHandler<string>? ModeRequested;

    public event EventHandler? AutostartToggled;

    public event EventHandler? ExitRequested;

    public event EventHandler? ResumeRequested;

    public void Update(StatusInfo? status, string mode, int pending)
    {
        var online = status is { Installed: true };
        var panic = online ? status!.Panic : "off";
        var text = status is null ? L.T("CrioFire: service not running")
            : !status.Installed ? L.T("CrioFire: not set up yet")
            : panic == "block" ? L.T("CrioFire: PANIC · all network traffic blocked")
            : panic == "allow" ? L.T("CrioFire: PANIC · everything allowed, rules paused")
            : $"CrioFire: protected · {AppModel.ModeName(mode)} mode" + (pending > 0 ? $" · {pending} waiting" : string.Empty);
        _resume.Visible = panic != "off";
        _icon.Text = text.Length > 120 ? text[..120] : text;

        foreach (var item in new[] { _learning, _ask, _allowList })
        {
            item.Enabled = online;
        }

        _learning.Checked = online && mode == "learning";
        _ask.Checked = online && mode == "ask";
        _allowList.Checked = online && mode == "allowlist";

        var state = !online ? State.Offline : pending > 0 || panic != "off" ? State.Pending : State.Normal;
        if (state != _state)
        {
            _state = state;
            if (!_icons.TryGetValue(state, out var icon))
            {
                icon = state == State.Normal ? _base : Derive(_base, gray: state == State.Offline, dot: state == State.Pending);
                _icons[state] = icon;
            }

            _icon.Icon = icon;
        }
    }

    public void ShowHint(string title, string text) => _icon.ShowBalloonTip(6000, title, text, Forms.ToolTipIcon.None);

    public void Dispose()
    {
        ThemeManager.Changed -= OnThemeChanged;
        _icon.Visible = false;
        _icon.Dispose();
        _menu.Dispose();
        foreach (var icon in _icons.Values.Where(i => i != _base))
        {
            icon.Dispose();
        }

        _base.Dispose();
    }

    private void OnThemeChanged(object? sender, EventArgs e) => ApplyTheme();

    /// <summary>The menu follows the app's light or dark theme.</summary>
    private void ApplyTheme()
    {
        var colors = new TrayMenuColors(ThemeManager.IsDark);
        _menu.Renderer = new Forms.ToolStripProfessionalRenderer(colors) { RoundedEdges = false };
        _menu.BackColor = colors.ToolStripDropDownBackground;
        foreach (Forms.ToolStripItem item in _menu.Items)
        {
            item.ForeColor = ThemeManager.IsDark ? Drawing.Color.FromArgb(0xE6, 0xED, 0xF7) : Drawing.Color.FromArgb(0x0E, 0x1A, 0x2B);
        }
    }

    /// <summary>A grayed-out icon (service down) or one with a fire-red dot (decisions waiting).</summary>
    private static Drawing.Icon Derive(Drawing.Icon source, bool gray, bool dot)
    {
        int w = source.Width, h = source.Height;
        using var bitmap = new Drawing.Bitmap(w, h, DrawingImaging.PixelFormat.Format32bppArgb);
        using (var g = Drawing.Graphics.FromImage(bitmap))
        using (var original = source.ToBitmap())
        {
            g.SmoothingMode = Drawing.Drawing2D.SmoothingMode.AntiAlias;
            var dest = new Drawing.Rectangle(0, 0, w, h);
            if (gray)
            {
                var matrix = new DrawingImaging.ColorMatrix(
                [
                    [0.30f, 0.30f, 0.30f, 0, 0],
                    [0.59f, 0.59f, 0.59f, 0, 0],
                    [0.11f, 0.11f, 0.11f, 0, 0],
                    [0, 0, 0, 0.7f, 0],
                    [0, 0, 0, 0, 1],
                ]);
                using var attributes = new DrawingImaging.ImageAttributes();
                attributes.SetColorMatrix(matrix);
                g.DrawImage(original, dest, 0, 0, w, h, Drawing.GraphicsUnit.Pixel, attributes);
            }
            else
            {
                g.DrawImage(original, dest);
            }

            if (dot)
            {
                var d = Math.Max(6f, w * 0.5f);
                var r = new Drawing.RectangleF(w - d, h - d, d - 1, d - 1);
                using var fill = new Drawing.SolidBrush(Drawing.Color.FromArgb(0xFF, 0x4A, 0x32));
                using var ring = new Drawing.Pen(Drawing.Color.White, Math.Max(1f, w / 16f));
                g.FillEllipse(fill, r);
                g.DrawEllipse(ring, r);
            }
        }

        var handle = bitmap.GetHicon();
        try
        {
            using var temporary = Drawing.Icon.FromHandle(handle);
            return (Drawing.Icon)temporary.Clone();
        }
        finally
        {
            DestroyIcon(handle);
        }
    }

    [LibraryImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool DestroyIcon(nint handle);

    private sealed class TrayMenuColors(bool dark) : Forms.ProfessionalColorTable
    {
        private readonly Drawing.Color _background = dark ? Drawing.Color.FromArgb(0x0F, 0x1A, 0x2B) : Drawing.Color.FromArgb(0xFB, 0xFD, 0xFF);
        private readonly Drawing.Color _hover = dark ? Drawing.Color.FromArgb(0x1A, 0x34, 0x4D) : Drawing.Color.FromArgb(0xD9, 0xEF, 0xFB);
        private readonly Drawing.Color _border = dark ? Drawing.Color.FromArgb(0x27, 0x3A, 0x55) : Drawing.Color.FromArgb(0xC9, 0xD6, 0xE5);

        public override Drawing.Color ToolStripDropDownBackground => _background;

        public override Drawing.Color ImageMarginGradientBegin => _background;

        public override Drawing.Color ImageMarginGradientMiddle => _background;

        public override Drawing.Color ImageMarginGradientEnd => _background;

        public override Drawing.Color MenuBorder => _border;

        public override Drawing.Color MenuItemBorder => _hover;

        public override Drawing.Color MenuItemSelected => _hover;

        public override Drawing.Color MenuItemSelectedGradientBegin => _hover;

        public override Drawing.Color MenuItemSelectedGradientEnd => _hover;

        public override Drawing.Color SeparatorDark => _border;

        public override Drawing.Color SeparatorLight => _background;

        public override Drawing.Color CheckBackground => _hover;

        public override Drawing.Color CheckSelectedBackground => _hover;

        public override Drawing.Color CheckPressedBackground => _hover;
    }
}
