using System.Net;
using System.Security.Principal;
using CrioFire.Core;
using CrioFire.Core.Api;

namespace CrioFire.IntegrationTests;

/// <summary>
/// End-to-end tests of the local API: a real pipe server (as the service runs it) on a private
/// pipe name, a real client, and real filters.
/// </summary>
public sealed class ApiTests : IAsyncDisposable
{
    private readonly string _pipeName = $"criofire-test-{Guid.NewGuid():N}";
    private readonly CancellationTokenSource _stop = new();
    private WfpEngine? _engine;
    private Task? _server;

    public async ValueTask DisposeAsync()
    {
        await _stop.CancelAsync();
        if (_server is not null)
        {
            try
            {
                await _server;
            }
            catch (OperationCanceledException)
            {
            }
        }

        if (_engine is not null)
        {
            _engine.Uninstall();
            _engine.Dispose();
        }

        _stop.Dispose();
    }

    [Fact]
    public void StatusListAndRulesWorkThroughThePipe()
    {
        using var client = Connect();

        var status = client.Send(new ApiRequest { Op = ApiOps.Status });
        Assert.True(status.Ok, status.Error);
        Assert.True(status.Status!.Installed);
        Assert.Equal("learning", status.Status.Mode);

        var set = client.Send(new ApiRequest { Op = ApiOps.SetRule, App = Peer.ExePath, Action = "block", Direction = "both" });
        Assert.True(set.Ok, set.Error);
        Assert.Equal(4, set.Count);

        var list = client.Send(new ApiRequest { Op = ApiOps.List });
        Assert.Equal(4, list.Rules!.Count(r => string.Equals(r.App, Peer.ExePath, StringComparison.OrdinalIgnoreCase) && r.Action == "block"));

        var removed = client.Send(new ApiRequest { Op = ApiOps.RemoveRules, App = Peer.ExePath });
        Assert.Equal(4, removed.Count);
    }

    [Fact]
    public async Task ARuleSetThroughThePipeReallyBlocksAndIsReported()
    {
        using var client = Connect();
        using var listener = new LocalListener(IPAddress.Loopback);

        Assert.True(client.Send(new ApiRequest { Op = ApiOps.SetRule, App = Peer.ExePath, Action = "block" }).Ok);
        var attempt = await Peer.ConnectAsync(IPAddress.Loopback, listener.Port);
        Assert.True(attempt.ExitCode != 0, $"Should be blocked: {attempt.Output}");

        EventInfo? hit = null;
        for (var i = 0; i < 40 && hit is null; i++)
        {
            hit = client.Send(new ApiRequest { Op = ApiOps.Events, Minutes = 5 }).Events!
                .FirstOrDefault(e => e.Remote?.EndsWith($":{listener.Port}", StringComparison.Ordinal) == true);
            if (hit is null)
            {
                await Task.Delay(250, TestContext.Current.CancellationToken);
            }
        }

        Assert.NotNull(hit);
        Assert.True(hit.CrioFire);
        Assert.Equal("out", hit.Direction);
        Assert.Equal(Peer.ExePath, hit.App, ignoreCase: true);
    }

    [Fact]
    public void ModeAndPanicWorkThroughThePipe()
    {
        using var client = Connect();

        var mode = client.Send(new ApiRequest { Op = ApiOps.SetMode, Mode = "ask" });
        Assert.True(mode.Ok, mode.Error);
        Assert.Equal("ask", mode.Mode);
        Assert.Equal("ask", client.Send(new ApiRequest { Op = ApiOps.Status }).Status!.Mode);

        var pause = client.Send(new ApiRequest { Op = ApiOps.Panic, Action = "allow" });
        Assert.True(pause.Ok, pause.Error);
        Assert.Equal("allow", pause.Panic);
        var paused = client.Send(new ApiRequest { Op = ApiOps.Status }).Status!;
        Assert.Equal("allow", paused.Panic);
        Assert.Equal("ask", paused.Mode);   // rules and mode are kept

        var resume = client.Send(new ApiRequest { Op = ApiOps.Panic, Action = "off" });
        Assert.True(resume.Ok, resume.Error);
        Assert.Equal("off", client.Send(new ApiRequest { Op = ApiOps.Status }).Status!.Panic);

        Assert.False(client.Send(new ApiRequest { Op = ApiOps.Panic }).Ok);   // the action is required

        var panic = client.Send(new ApiRequest { Op = ApiOps.Panic, Action = "remove" });
        Assert.True(panic.Ok);
        Assert.True(panic.Count > 0);
        Assert.Equal("learning", client.Send(new ApiRequest { Op = ApiOps.Status }).Status!.Mode);
    }

    [Fact]
    public void BadRequestsGetErrorsAndTheConnectionStaysUsable()
    {
        using var client = Connect();

        var unknown = client.Send(new ApiRequest { Op = "nonsense" });
        Assert.False(unknown.Ok);

        var badAction = client.Send(new ApiRequest { Op = ApiOps.SetRule, App = Peer.ExePath, Action = "maybe" });
        Assert.False(badAction.Ok);
        Assert.Contains("block or allow", badAction.Error);

        var missing = client.Send(new ApiRequest { Op = ApiOps.SetRule, App = @"C:\no\such\app.exe", Action = "block" });
        Assert.False(missing.Ok);

        Assert.True(client.Send(new ApiRequest { Op = ApiOps.Status }).Ok);
    }

    [Fact]
    public void SeveralClientsCanConnectAtOnce()
    {
        using var a = Connect();
        using var b = CrioFireClient.TryConnect(_pipeName, 5000) ?? throw new InvalidOperationException("Second client could not connect.");
        Assert.True(a.Send(new ApiRequest { Op = ApiOps.Status }).Ok);
        Assert.True(b.Send(new ApiRequest { Op = ApiOps.Status }).Ok);
    }

    [Fact]
    public void ASecondServerCannotTakeOverThePipeName()
    {
        using var client = Connect();   // starts our server

        using var engine = WfpEngine.Open();
        var squatter = new ApiServer(new ApiHandler(engine), _pipeName);
        var ex = Assert.ThrowsAny<Exception>(() => squatter.RunAsync(CancellationToken.None).GetAwaiter().GetResult());
        Assert.True(ex is UnauthorizedAccessException or IOException, $"Expected access denied, got {ex.GetType().Name}: {ex.Message}");
    }

    private CrioFireClient Connect()
    {
        Assert.SkipUnless(Environment.GetEnvironmentVariable("CRIOFIRE_INTEGRATION") == "1",
            "Set CRIOFIRE_INTEGRATION=1 to run tests that change the firewall.");
        Assert.True(IsAdministrator(), "CRIOFIRE_INTEGRATION=1 is set, but firewall tests need an administrator terminal.");

        if (_engine is null)
        {
            _engine = WfpEngine.Open();
            _engine.Uninstall();
            _engine.Install();
            var server = new ApiServer(new ApiHandler(_engine), _pipeName);
            _server = Task.Run(() => server.RunAsync(_stop.Token));
        }

        return CrioFireClient.TryConnect(_pipeName, 5000) ?? throw new InvalidOperationException("Could not connect to the test API server.");
    }

    private static bool IsAdministrator()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }
}
