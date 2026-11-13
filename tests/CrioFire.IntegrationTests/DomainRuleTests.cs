using System.Net;
using System.Net.Sockets;
using System.Security.Principal;
using CrioFire.Core;

namespace CrioFire.IntegrationTests;

/// <summary>
/// Domain rules against the real filtering platform and Windows' real DNS client. The address
/// filter tests use a documentation address (203.0.113.9) that goes nowhere; the lookup tests need
/// the runner's internet connection (example.com).
/// </summary>
public sealed class DomainRuleTests : IDisposable
{
    private static readonly IPAddress Nowhere = IPAddress.Parse("203.0.113.9");

    private WfpEngine? _engine;

    public void Dispose()
    {
        if (_engine is not null)
        {
            _engine.Uninstall();
            _engine.Dispose();
        }
    }

    [Fact]
    public async Task AnAddressFilterBlocksAndGoesAway()
    {
        var engine = Engine();
        var rule = new DomainRule("test1", "example.invalid", RuleAction.Block);
        Assert.False(await TcpBlocked(Nowhere), "Baseline: the address was blocked before any rule.");

        engine.AddDomainAddress(rule, Nowhere);
        var listed = Assert.Single(engine.ListDomainAddresses());
        Assert.Equal(new DomainAddress("test1", RuleAction.Block, NetworkProfiles.Any, Nowhere, null), listed.Address);
        Assert.True(await TcpBlocked(Nowhere), "The domain's address filter did not block.");

        engine.RemoveFilters([listed.FilterId]);
        Assert.Empty(engine.ListDomainAddresses());
        Assert.False(await TcpBlocked(Nowhere), "The address stayed blocked after its filter was removed.");
    }

    [Fact]
    public async Task ARuleBlocksWhatItsDomainResolvesTo()
    {
        var engine = Engine();
        var addresses = Resolve("example.com");
        Assert.SkipWhen(addresses.Count == 0, "example.com does not resolve on this machine (no internet?).");
        var target = addresses.First(a => a.AddressFamily == AddressFamily.InterNetwork);
        Assert.False(await TcpBlocked(target, 80), "Baseline: example.com was blocked before any rule.");

        var keeper = new DomainKeeper(engine, _ => addresses);   // the same answer the target came from
        keeper.Reset([new DomainRule("test2", "example.com", RuleAction.Block)], DateTime.UtcNow);

        Assert.True(await TcpBlocked(target, 80), "The rule for example.com did not block its address.");
        keeper.Update([], DateTime.UtcNow);
        Assert.False(await TcpBlocked(target, 80), "example.com stayed blocked after its rule was removed.");
    }

    [Fact]
    public async Task WindowsLookupsAreFollowed()
    {
        Assert.SkipUnless(Environment.GetEnvironmentVariable("CRIOFIRE_INTEGRATION") == "1",
            "Set CRIOFIRE_INTEGRATION=1 to run tests that need administrator rights.");
        Assert.True(IsAdministrator(), "Following lookups needs an administrator terminal.");

        var seen = new TaskCompletionSource<DnsLookup>(TaskCreationOptions.RunContinuationsAsynchronously);
        using var events = new DnsClientEvents();
        events.Lookup += lookup =>
        {
            if (DomainNames.Covers("example.com", lookup.Name))
            {
                seen.TrySetResult(lookup);
            }
        };
        events.Start();

        // Windows answers repeated lookups from its cache, and those complete as events too.
        for (var i = 0; i < 10 && !seen.Task.IsCompleted; i++)
        {
            Resolve(i % 2 == 0 ? "example.com" : "www.example.com");
            await Task.WhenAny(seen.Task, Task.Delay(1000, TestContext.Current.CancellationToken));
        }

        Assert.True(seen.Task.IsCompleted, "No completed lookup of example.com was seen within 10 seconds.");
        var lookup = await seen.Task;
        Assert.NotEmpty(lookup.Addresses);
    }

    private static List<IPAddress> Resolve(string name)
    {
        try
        {
            return [.. Dns.GetHostAddresses(name)];
        }
        catch (SocketException)
        {
            return [];
        }
    }

    /// <summary>A blocked TCP connect fails at once with "access denied"; an allowed one connects or times out.</summary>
    private static async Task<bool> TcpBlocked(IPAddress address, int port = 9)
    {
        using var socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(3));
        try
        {
            await socket.ConnectAsync(new IPEndPoint(address, port), timeout.Token);
            return false;
        }
        catch (SocketException ex) when (ex.SocketErrorCode == SocketError.AccessDenied)
        {
            return true;
        }
        catch (Exception ex) when (ex is OperationCanceledException or SocketException)
        {
            return false;
        }
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
