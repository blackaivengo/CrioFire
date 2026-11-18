using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using CrioFire.Core;

namespace CrioFire.App;

/// <summary>
/// Network tools for a connection's remote address: ping, trace route, name lookup, the open
/// connections with it and a port test, with their output here; and SSH, Remote Desktop, Telnet
/// or a PowerShell connection test in a window of their own. Only IP addresses get here
/// (<see cref="NetworkTools.Address"/>), so nothing else reaches a command line.
/// </summary>
public partial class NetworkToolsWindow : Window
{
    private readonly AppModel _model;
    private readonly string _address;
    private Process? _process;
    private CancellationTokenSource? _portTest;
    private int _run;

    static NetworkToolsWindow() => Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);

    private NetworkToolsWindow(AppModel model, string address, int port)
    {
        _model = model;
        _address = address;
        InitializeComponent();
        var scope = NetworkFacts.AddressScope(address);
        TitleText.Text = L.T($"Network tools · {address}");
        SubtitleText.Text = scope;
        OwnerButton.IsEnabled = scope == "internet";
        PortBox.Text = port is > 0 and <= 65535 ? port.ToString(CultureInfo.InvariantCulture) : string.Empty;
        UpdatePortButtons();

        SshButton.IsEnabled = Exists(Path.Combine(Environment.SystemDirectory, "OpenSSH", "ssh.exe"));
        if (!SshButton.IsEnabled)
        {
            SshButton.ToolTip = L.T("The OpenSSH client is not installed (Settings → System → Optional features).");
        }

        TelnetButton.Tag = Exists(Path.Combine(Environment.SystemDirectory, "telnet.exe"));
        if (TelnetButton.Tag is false)
        {
            TelnetButton.ToolTip = L.T("The Telnet client is not installed (Windows features → Telnet Client).");
        }

        UpdatePortButtons();
        MouseLeftButtonDown += (_, e) =>
        {
            if (e.ButtonState == MouseButtonState.Pressed && e.OriginalSource is not (Button or TextBox) && !IsInside(e.OriginalSource as DependencyObject))
            {
                DragMove();
            }
        };
        Closing += (_, _) => Stop();
    }

    /// <summary>Opens the tools for an address (an IP address; anything else is ignored), with the connection's port when known.</summary>
    internal static void Open(Window? owner, AppModel model, string? address, int port = 0)
    {
        if (NetworkTools.Address(address) is not { } ip)
        {
            model.Say(L.T("Network tools work with IP addresses only."));
            return;
        }

        var window = new NetworkToolsWindow(model, ip, port);
        if (owner is { IsVisible: true } && owner is not AlertWindow)
        {
            window.Owner = owner;
        }
        else
        {
            // From an alert: not owned by it, so it stays open when the alert closes.
            window.WindowStartupLocation = WindowStartupLocation.CenterScreen;
            window.Topmost = owner is AlertWindow;
        }

        window.Show();
        window.Activate();
    }

    private int? Port => int.TryParse(PortBox.Text, NumberStyles.None, CultureInfo.InvariantCulture, out var p) && p is > 0 and <= 65535 ? p : null;

    private void OnPortChanged(object sender, TextChangedEventArgs e) => UpdatePortButtons();

    private void UpdatePortButtons()
    {
        if (TestPortButton is null)
        {
            return;   // during InitializeComponent
        }

        var hasPort = Port is not null;
        TestPortButton.IsEnabled = hasPort;
        PowerShellButton.IsEnabled = hasPort;
        TelnetButton.IsEnabled = hasPort && TelnetButton.Tag is not false;
    }

    private void OnPing(object sender, RoutedEventArgs e) => _ = RunAsync(NetworkTools.Ping(_address), L.T("Ping"));

    private void OnTraceRoute(object sender, RoutedEventArgs e) =>
        _ = RunAsync(NetworkTools.TraceRoute(_address), L.T("Trace route"), L.T("Tracing the route; each hop can take a few seconds…"));

    private void OnNameLookup(object sender, RoutedEventArgs e) => _ = RunAsync(NetworkTools.NameLookup(_address), L.T("Name lookup"));

    private void OnConnections(object sender, RoutedEventArgs e) => _ = RunAsync(NetworkTools.Connections(), L.T("Connections"), filter: lines =>
    {
        var found = NetworkTools.ConnectionsWith(lines, _address, ProcessName);
        return found.Count == 0 ? [L.T($"No open connections with {_address} right now.")] : found;
    });

    private void OnOwner(object sender, RoutedEventArgs e) => RowMenu.Browse(NetworkTools.OwnerUrl(_address));

    private async void OnTestPort(object sender, RoutedEventArgs e)
    {
        if (Port is not { } port)
        {
            return;
        }

        Stop();
        var run = ++_run;
        Output.Clear();
        Append(L.T($"Connecting to {_address} port {port} (TCP)…"));
        Busy(true, L.T("Testing the port…"));
        using var cancel = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        _portTest = cancel;
        var watch = Stopwatch.StartNew();
        string result;
        try
        {
            var ip = IPAddress.Parse(_address);
            using var client = new TcpClient(ip.AddressFamily);
            await client.ConnectAsync(ip, port, cancel.Token);
            result = L.T($"Port {port} answers: a program on {_address} accepted the connection ({watch.ElapsedMilliseconds} ms).");
        }
        catch (OperationCanceledException)
        {
            result = L.T($"No answer from port {port} within 5 seconds: a firewall drops the connection, or the address is not reachable.");
        }
        catch (SocketException ex)
        {
            result = ex.SocketErrorCode == SocketError.ConnectionRefused
                ? L.T($"Port {port} refused the connection: the address is reachable, but nothing listens on that port.")
                : L.T($"Could not connect to port {port}: {ex.Message}");
        }
        finally
        {
            _portTest = null;
        }

        if (run == _run)
        {
            Append(result);
            Busy(false, result);
        }
    }

    private void OnSsh(object sender, RoutedEventArgs e) => Terminal(NetworkTools.Ssh(_address), console: true);

    private void OnRemoteDesktop(object sender, RoutedEventArgs e) => Terminal(NetworkTools.RemoteDesktop(_address), console: false);

    private void OnTelnet(object sender, RoutedEventArgs e)
    {
        if (Port is { } port)
        {
            Terminal(NetworkTools.Telnet(_address, port), console: true);
        }
    }

    private void OnPowerShell(object sender, RoutedEventArgs e)
    {
        if (Port is { } port)
        {
            Terminal(NetworkTools.PowerShellTest(_address, port), console: false);
        }
    }

    private void OnStop(object sender, RoutedEventArgs e)
    {
        Stop();
        Busy(false, L.T("Stopped."));
    }

    private void OnCopy(object sender, RoutedEventArgs e) => RowMenu.Copy(_model, Output.Text);

    private void OnClose(object sender, RoutedEventArgs e) => Close();

    /// <summary>Runs a Windows tool and shows what it prints; <paramref name="filter"/> instead shows a selection of it at the end.</summary>
    private async Task RunAsync(ToolCommand command, string name, string? busyText = null, Func<IReadOnlyList<string>, IReadOnlyList<string>>? filter = null)
    {
        Stop();
        var run = ++_run;
        Output.Clear();
        Append($"> {command.Program} {command.Arguments}");
        Append(string.Empty);
        Busy(true, busyText ?? L.T($"Running {name}…"));

        // Console tools write in the OEM code page when their output is redirected.
        var oem = Encoding.GetEncoding(CultureInfo.CurrentCulture.TextInfo.OEMCodePage);
        var start = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, command.Program), command.Arguments)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            StandardOutputEncoding = oem,
            StandardErrorEncoding = oem,
        };
        var collected = new List<string>();
        try
        {
            using var process = new Process { StartInfo = start, EnableRaisingEvents = true };
            DataReceivedEventHandler onLine = (_, e) =>
            {
                if (e.Data is null)
                {
                    return;
                }

                if (filter is not null)
                {
                    lock (collected)
                    {
                        collected.Add(e.Data);
                    }
                }
                else
                {
                    Dispatcher.BeginInvoke(() =>
                    {
                        if (run == _run)
                        {
                            Append(e.Data);
                        }
                    });
                }
            };
            process.OutputDataReceived += onLine;
            process.ErrorDataReceived += onLine;
            process.Start();
            _process = process;
            process.BeginOutputReadLine();
            process.BeginErrorReadLine();
            await process.WaitForExitAsync();
            if (run != _run)
            {
                return;   // stopped, or another tool started
            }

            _process = null;
            await Dispatcher.InvokeAsync(() => { }, System.Windows.Threading.DispatcherPriority.Background);   // let the last lines in
            if (filter is not null)
            {
                List<string> lines;
                lock (collected)
                {
                    lines = [.. collected];
                }

                foreach (var line in filter(lines))
                {
                    Append(line);
                }
            }

            Busy(false, L.T($"{name} finished."));
        }
        catch (Exception ex) when (ex is Win32Exception or InvalidOperationException or IOException)
        {
            if (run == _run)
            {
                _process = null;
                Append(ex.Message);
                Busy(false, L.T($"{name} could not run: {ex.Message}"));
            }
        }
    }

    /// <summary>Opens a tool in a window of its own: console ones inside a Command Prompt that stays open.</summary>
    private void Terminal(ToolCommand command, bool console)
    {
        try
        {
            // System32 paths have no spaces, so cmd /k needs no quotes around them.
            var tool = command.Program == "ssh.exe"
                ? Path.Combine(Environment.SystemDirectory, "OpenSSH", "ssh.exe")
                : Path.Combine(Environment.SystemDirectory, command.Program);
            var start = console
                ? new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "cmd.exe"), $"/k {tool} {command.Arguments}")
                : new ProcessStartInfo(command.Program, command.Arguments);
            start.UseShellExecute = true;
            Process.Start(start);
        }
        catch (Win32Exception ex)
        {
            _model.Say(L.T($"Could not open {command.Program}: {ex.Message}"));
        }
    }

    private void Stop()
    {
        _run++;
        _portTest?.Cancel();
        if (_process is { } process)
        {
            _process = null;
            try
            {
                process.Kill(entireProcessTree: true);
            }
            catch (Exception ex) when (ex is InvalidOperationException or Win32Exception or NotSupportedException)
            {
                // Already gone.
            }
        }
    }

    private void Busy(bool busy, string status)
    {
        StopButton.IsEnabled = busy;
        StatusText.Text = status;
        if (!busy)
        {
            ScreenReader.Say(this, status);
        }
    }

    private void Append(string line)
    {
        Output.AppendText(line + Environment.NewLine);
        Output.ScrollToEnd();
    }

    private static string? ProcessName(int pid)
    {
        try
        {
            using var process = Process.GetProcessById(pid);
            return process.ProcessName + ".exe";
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or Win32Exception)
        {
            return null;
        }
    }

    private static bool Exists(string path) => File.Exists(path);

    /// <summary>True for clicks inside the output box (selecting text, not moving the window).</summary>
    private bool IsInside(DependencyObject? node)
    {
        for (; node is not null; node = node is System.Windows.Media.Visual ? System.Windows.Media.VisualTreeHelper.GetParent(node) : LogicalTreeHelper.GetParent(node))
        {
            if (ReferenceEquals(node, Output) || node is System.Windows.Controls.Primitives.ScrollBar)
            {
                return true;
            }
        }

        return false;
    }
}
