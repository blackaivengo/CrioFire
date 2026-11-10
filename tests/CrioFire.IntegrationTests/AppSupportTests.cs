using System.Net;
using System.Net.Sockets;
using System.Security.Principal;
using CrioFire.Core;
using CrioFire.Core.Api;

namespace CrioFire.IntegrationTests;

/// <summary>The live connections view reads the real TCP/UDP tables; needs no administrator rights.</summary>
public class ConnectionTableTests
{
    [Fact]
    public async Task SeesOurListenerAndBothEndsOfAConnection()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;

        using var client = new TcpClient(AddressFamily.InterNetwork);
        await client.ConnectAsync(IPAddress.Loopback, port, TestContext.Current.CancellationToken);
        using var accepted = await listener.AcceptTcpClientAsync(TestContext.Current.CancellationToken);
        var clientPort = ((IPEndPoint)client.Client.LocalEndPoint!).Port;

        using var udp = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        var udpPort = ((IPEndPoint)udp.Client.LocalEndPoint!).Port;

        var pid = Environment.ProcessId;
        var ours = ConnectionTable.Read().Where(c => c.ProcessId == pid).ToList();

        Assert.Contains(ours, c => c.Protocol == ProtocolType.Tcp && c.State == "Listening" && c.Local.Port == port && c.Remote is null);
        Assert.Contains(ours, c => c.State == "Established" && c.Local.Port == clientPort && c.Remote?.Port == port
                                   && c.Remote.Address.Equals(IPAddress.Loopback));
        Assert.Contains(ours, c => c.State == "Established" && c.Local.Port == port && c.Remote?.Port == clientPort);
        Assert.Contains(ours, c => c.Protocol == ProtocolType.Udp && c.Local.Port == udpPort && c.ProtocolName == "UDP");

        var path = ours.First().ProcessPath;
        Assert.NotNull(path);
        Assert.Equal(Environment.ProcessPath, path, ignoreCase: true);
    }
}

/// <summary>Temporary rules ("allow for 1 hour") end to end: the rule is created, listed with its expiry, and removed when due.</summary>
public sealed class TemporaryRuleTests : IDisposable
{
    private readonly string _storePath = Path.Combine(Path.GetTempPath(), $"criofire-temp-rules-{Guid.NewGuid():N}.json");
    private WfpEngine? _engine;

    public void Dispose()
    {
        if (_engine is not null)
        {
            _engine.Uninstall();
            _engine.Dispose();
        }

        File.Delete(_storePath);
    }

    [Fact]
    public async Task ATemporaryBlockExpiresAndTheProgramCanConnectAgain()
    {
        var engine = Engine();
        var store = new TemporaryRuleStore(_storePath);
        var handler = new ApiHandler(engine, store);
        using var listener = new LocalListener(IPAddress.Loopback);

        var set = handler.Handle(new ApiRequest { Op = ApiOps.SetRule, App = Peer.ExePath, Action = "block", ExpiresMinutes = 60 }, canWrite: true);
        Assert.True(set.Ok, set.Error);

        var listed = handler.Handle(new ApiRequest { Op = ApiOps.List }, canWrite: false).Rules!
            .Where(r => string.Equals(r.App, Peer.ExePath, StringComparison.OrdinalIgnoreCase)).ToList();
        Assert.NotEmpty(listed);
        Assert.All(listed, r => Assert.NotNull(r.ExpiresUtc));

        var blocked = await Peer.ConnectAsync(IPAddress.Loopback, listener.Port);
        Assert.True(blocked.ExitCode != 0, $"The temporary block should stop the peer: {blocked.Output}");

        Assert.Equal(0, store.ExpireDue(engine, DateTime.UtcNow));               // not due yet
        Assert.Equal(1, store.ExpireDue(engine, DateTime.UtcNow.AddMinutes(61))); // an hour later

        Assert.DoesNotContain(engine.ListFilters(), f => string.Equals(f.Rule?.AppPath, Peer.ExePath, StringComparison.OrdinalIgnoreCase));
        var allowed = await Peer.ConnectAsync(IPAddress.Loopback, listener.Port);
        Assert.True(allowed.ExitCode == 0, $"After expiry the peer should connect again: {allowed.Output}");
    }

    [Fact]
    public void MakingARulePermanentForgetsItsExpiry()
    {
        var engine = Engine();
        var store = new TemporaryRuleStore(_storePath);
        var handler = new ApiHandler(engine, store);

        Assert.True(handler.Handle(new ApiRequest { Op = ApiOps.SetRule, App = Peer.ExePath, Action = "allow", ExpiresMinutes = 5 }, canWrite: true).Ok);
        Assert.Single(store.All());

        Assert.True(handler.Handle(new ApiRequest { Op = ApiOps.SetRule, App = Peer.ExePath, Action = "allow" }, canWrite: true).Ok);
        Assert.Empty(store.All());
        Assert.Equal(0, store.ExpireDue(engine, DateTime.UtcNow.AddDays(1)));
        Assert.Contains(engine.ListFilters(), f => string.Equals(f.Rule?.AppPath, Peer.ExePath, StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void ExpiryOutOfRangeIsRefused()
    {
        var handler = new ApiHandler(Engine(), new TemporaryRuleStore(_storePath));
        var response = handler.Handle(new ApiRequest { Op = ApiOps.SetRule, App = Peer.ExePath, Action = "allow", ExpiresMinutes = 0 }, canWrite: true);
        Assert.False(response.Ok);
    }

    private WfpEngine Engine()
    {
        Assert.SkipUnless(Environment.GetEnvironmentVariable("CRIOFIRE_INTEGRATION") == "1",
            "Set CRIOFIRE_INTEGRATION=1 to run tests that change the firewall.");
        Assert.True(IsAdministrator(), "CRIOFIRE_INTEGRATION=1 is set, but firewall tests need an administrator terminal.");

        if (_engine is null)
        {
            _engine = WfpEngine.Open();
            _engine.Uninstall();
            _engine.Install();
        }

        return _engine;
    }

    private static bool IsAdministrator()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }
}
