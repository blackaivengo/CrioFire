using System.Globalization;
using System.Net;
using System.Net.Sockets;

// CrioFire.TestPeer.exe connect <address> <port> [timeoutMs]
//   exit 0 = connected, 1 = refused or blocked, 2 = timed out
// CrioFire.TestPeer.exe listen <address> <seconds>
//   prints "port <n>" once listening; exit 0 = a client connected, 1 = nobody connected in time

if (args.Length < 3)
{
    Console.Error.WriteLine("usage: connect <address> <port> [timeoutMs] | listen <address> <seconds>");
    return 64;
}

var address = IPAddress.Parse(args[1]);

switch (args[0])
{
    case "connect":
    {
        var port = int.Parse(args[2], CultureInfo.InvariantCulture);
        var timeout = args.Length > 3 ? int.Parse(args[3], CultureInfo.InvariantCulture) : 3000;
        using var client = new TcpClient(address.AddressFamily);
        using var cts = new CancellationTokenSource(timeout);
        try
        {
            await client.ConnectAsync(address, port, cts.Token);
            Console.WriteLine("connected");
            return 0;
        }
        catch (OperationCanceledException)
        {
            Console.WriteLine("timeout");
            return 2;
        }
        catch (SocketException ex)
        {
            Console.WriteLine($"socket error {ex.SocketErrorCode} ({ex.NativeErrorCode})");
            return 1;
        }
    }

    case "listen":
    {
        var seconds = int.Parse(args[2], CultureInfo.InvariantCulture);
        var listener = new TcpListener(address, 0);
        listener.Start();
        Console.WriteLine($"port {((IPEndPoint)listener.LocalEndpoint).Port}");
        Console.Out.Flush();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(seconds));
        try
        {
            using var accepted = await listener.AcceptTcpClientAsync(cts.Token);
            Console.WriteLine("accepted");
            return 0;
        }
        catch (OperationCanceledException)
        {
            Console.WriteLine("nobody connected");
            return 1;
        }
        finally
        {
            listener.Stop();
        }
    }

    default:
        Console.Error.WriteLine($"unknown mode {args[0]}");
        return 64;
}
