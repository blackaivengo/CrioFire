using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Reflection;

namespace CrioFire.IntegrationTests;

/// <summary>Runs CrioFire.TestPeer.exe, the program the tests block and unblock.</summary>
internal static class Peer
{
    public static string ExePath { get; } = Path.GetFullPath(
        typeof(Peer).Assembly.GetCustomAttributes<AssemblyMetadataAttribute>().Single(a => a.Key == "TestPeerPath").Value!);

    /// <summary>The peer connects to <paramref name="address"/>:<paramref name="port"/>. Returns its exit code (0 = connected).</summary>
    public static async Task<(int ExitCode, string Output)> ConnectAsync(IPAddress address, int port)
    {
        using var process = Start("connect", address.ToString(), port.ToString(CultureInfo.InvariantCulture), "3000");
        var output = await process.StandardOutput.ReadToEndAsync();
        await WaitAsync(process, TimeSpan.FromSeconds(15));
        return (process.ExitCode, output.Trim());
    }

    /// <summary>
    /// The peer listens on <paramref name="address"/>; the test process then connects to it.
    /// Returns whether the test's connection succeeded and the peer's exit code (0 = accepted).
    /// </summary>
    public static async Task<(bool Connected, int PeerExitCode)> ListenAndConnectAsync(IPAddress address)
    {
        using var process = Start("listen", address.ToString(), "6");
        var line = await process.StandardOutput.ReadLineAsync() ?? throw new InvalidOperationException("Peer did not start listening.");
        var port = int.Parse(line.Split(' ')[1], CultureInfo.InvariantCulture);

        var connected = false;
        using (var client = new TcpClient(address.AddressFamily))
        using (var cts = new CancellationTokenSource(TimeSpan.FromSeconds(3)))
        {
            try
            {
                await client.ConnectAsync(address, port, cts.Token);
                connected = true;
            }
            catch (Exception ex) when (ex is SocketException or OperationCanceledException)
            {
                connected = false;
            }
        }

        await WaitAsync(process, TimeSpan.FromSeconds(15));
        return (connected, process.ExitCode);
    }

    private static Process Start(params string[] args)
    {
        Assert.True(File.Exists(ExePath), $"Test peer not built at {ExePath}");
        var info = new ProcessStartInfo(ExePath)
        {
            RedirectStandardOutput = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        foreach (var arg in args)
        {
            info.ArgumentList.Add(arg);
        }

        return Process.Start(info) ?? throw new InvalidOperationException("Could not start the test peer.");
    }

    private static async Task WaitAsync(Process process, TimeSpan timeout)
    {
        using var cts = new CancellationTokenSource(timeout);
        try
        {
            await process.WaitForExitAsync(cts.Token);
        }
        catch (OperationCanceledException)
        {
            process.Kill(entireProcessTree: true);
            throw new TimeoutException("Test peer did not exit in time.");
        }
    }
}

/// <summary>A one-shot TCP listener inside the test process (which CrioFire never blocks).</summary>
internal sealed class LocalListener : IDisposable
{
    private readonly TcpListener _listener;

    public LocalListener(IPAddress address)
    {
        _listener = new TcpListener(address, 0);
        _listener.Start();
        Port = ((IPEndPoint)_listener.LocalEndpoint).Port;
        _ = AcceptLoopAsync();
    }

    public int Port { get; }

    public void Dispose() => _listener.Stop();

    private async Task AcceptLoopAsync()
    {
        try
        {
            while (true)
            {
                using var client = await _listener.AcceptTcpClientAsync();
            }
        }
        catch (Exception ex) when (ex is SocketException or ObjectDisposedException)
        {
            // Listener stopped.
        }
    }
}
