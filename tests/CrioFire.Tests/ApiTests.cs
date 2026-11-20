using CrioFire.Core;
using CrioFire.Core.Api;

namespace CrioFire.Tests;

public class ApiProtocolTests
{
    [Fact]
    public void RequestRoundTripsAsOneLine()
    {
        var request = new ApiRequest { Op = ApiOps.SetMode, Mode = "allowlist", Apps = [@"C:\a.exe", @"C:\b c\d.exe"] };
        var line = ApiJson.Serialize(request);
        Assert.DoesNotContain('\n', line);
        Assert.Contains("\"op\":\"setMode\"", line);
        Assert.DoesNotContain("filterId", line);   // nulls are left out

        var back = ApiJson.DeserializeRequest(line)!;
        Assert.Equal(request.Op, back.Op);
        Assert.Equal(request.Mode, back.Mode);
        Assert.Equal(request.Apps, back.Apps);
    }

    [Fact]
    public void ResponseRoundTrips()
    {
        var response = new ApiResponse
        {
            Ok = true,
            Status = new StatusInfo(true, "ask", 6, "0.1.0"),
            Rules = [new RuleInfo(42, "AppRule", "block", "out", @"C:\a.exe", "outbound IPv4", "CrioFire: block a.exe")],
            Events = [new EventInfo(new DateTime(2026, 11, 9, 1, 2, 3, DateTimeKind.Utc), @"C:\a.exe", "TCP", null, "1.2.3.4:443", "out", true, 42)],
        };

        var back = ApiJson.DeserializeResponse(ApiJson.Serialize(response))!;
        Assert.True(back.Ok);
        Assert.Equal(response.Status, back.Status);
        Assert.Equal(response.Rules, back.Rules);
        Assert.Equal(response.Events, back.Events);
    }

    [Fact]
    public void RuleInfoDescribesEachKind()
    {
        var rule = new CrioFireFilter(1, "n", FilterLayers.ConnectV4, new RuleDescription(RuleAction.Allow, TrafficDirection.Both, @"C:\a.exe"));
        Assert.Equal(new RuleInfo(1, "AppRule", "allow", "both", @"C:\a.exe", "outbound IPv4", "n"), RuleInfo.From(rule));

        var catchAll = new CrioFireFilter(2, "m", FilterLayers.ConnectV6, null, FilterKind.DefaultBlock, FirewallMode.Ask);
        Assert.Equal("block", RuleInfo.From(catchAll).Action);
        Assert.Null(RuleInfo.From(catchAll).App);
    }

    [Theory]
    [InlineData(ApiOps.SetRule)]
    [InlineData(ApiOps.RemoveRules)]
    [InlineData(ApiOps.RemoveFilter)]
    [InlineData(ApiOps.SetMode)]
    [InlineData(ApiOps.Panic)]
    public void WritesAreRefusedWithoutPermission(string op)
    {
        // Refused before the engine is touched, so no engine is needed here.
        var handler = new ApiHandler(null!);
        var response = handler.Handle(new ApiRequest { Op = op }, canWrite: false);
        Assert.False(response.Ok);
        Assert.Contains("Not allowed", response.Error);
    }

    [Fact]
    public void UnknownOperationIsRefused()
    {
        var response = new ApiHandler(null!).Handle(new ApiRequest { Op = "format-c" }, canWrite: true);
        Assert.False(response.Ok);
        Assert.Contains("Unknown operation", response.Error);
    }
}

public class ApiAuthorizationTests
{
    private const string Install = @"C:\Program Files\CrioFire";

    [Theory]
    [InlineData(@"C:\Program Files\CrioFire\criofire-ui.exe", true)]
    [InlineData(@"C:\PROGRAM FILES\CRIOFIRE\CRIOFIRE-UI.EXE", true)]
    [InlineData(@"C:\Program Files\CrioFire\criofire.exe", false)]   // the command line: any program could run it
    [InlineData(@"C:\Program Files\CrioFire\criofire-svc.exe", false)]
    [InlineData(@"C:\Program Files\CrioFire\other.exe", false)]
    [InlineData(@"C:\Users\x\Downloads\criofire.exe", false)]
    [InlineData(@"C:\Program Files\CrioFire\sub\criofire.exe", false)]
    [InlineData(@"C:\Program Files\CrioFire\..\Evil\criofire.exe", false)]
    [InlineData(null, false)]
    public void OnlyTheAppFromTheInstallFolderMayWrite(string? path, bool expected) =>
        Assert.Equal(expected, ApiAuthorization.CanWrite(clientIsElevatedAdmin: false, path, Install));

    [Fact]
    public void ElevatedAdministratorsMayAlwaysWrite() =>
        Assert.True(ApiAuthorization.CanWrite(clientIsElevatedAdmin: true, @"C:\anything\tool.exe", Install));

    [Fact]
    public void TrailingSeparatorOnTheInstallFolderDoesNotMatter() =>
        Assert.True(ApiAuthorization.CanWrite(false, @"C:\Program Files\CrioFire\criofire-ui.exe", Install + @"\"));
}

public class DiagnosticsTests
{
    [Fact]
    public void TheServiceSaysHowMuchMemoryItUsesAndOfWhatKind()
    {
        var handler = new ApiHandler(null!);

        var memory = handler.Handle(new ApiRequest { Op = ApiOps.Diagnostics }, ClientRights.ReadOnly).Memory!;
        Assert.True(memory.PrivateBytes > 0 && memory.ManagedBytes > 0 && memory.Threads > 0);
        Assert.False(memory.Collected);

        // Collecting first stops everything for a moment: only for administrators.
        Assert.False(handler.Handle(new ApiRequest { Op = ApiOps.Diagnostics, All = true }, ClientRights.CrioFireApp).Memory!.Collected);
        var collected = handler.Handle(new ApiRequest { Op = ApiOps.Diagnostics, All = true }, ClientRights.Administrator).Memory!;
        Assert.True(collected.Collected);
        Assert.Contains("private ", collected.Describe(), StringComparison.Ordinal);
        Assert.Contains("after a full collection", collected.Describe(), StringComparison.Ordinal);
    }
}

public class RequestReaderTests
{
    private static RequestReader Reader(string text, int max = 64) => new(new MemoryStream(System.Text.Encoding.UTF8.GetBytes(text)), max);

    [Fact]
    public async Task ReadsLineByLine()
    {
        var reader = Reader("{\"op\":\"status\"}\n{\"op\":\"list\"}\r\nlast");
        Assert.Equal("{\"op\":\"status\"}", await reader.ReadLineAsync(TestContext.Current.CancellationToken));
        Assert.Equal("{\"op\":\"list\"}", await reader.ReadLineAsync(TestContext.Current.CancellationToken));
        Assert.Equal("last", await reader.ReadLineAsync(TestContext.Current.CancellationToken));
        Assert.Null(await reader.ReadLineAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task ALineLongerThanAnyRequestIsCutOff()
    {
        // 100,000 bytes and no line break: refused after the limit, not collected.
        var reader = Reader(new string('x', 100_000), max: 1000);
        await Assert.ThrowsAsync<InvalidDataException>(() => reader.ReadLineAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task ALineOfExactlyTheLimitIsRead()
    {
        var reader = Reader(new string('x', 1000) + "\n", max: 1000);
        Assert.Equal(1000, (await reader.ReadLineAsync(TestContext.Current.CancellationToken))!.Length);
    }

    [Fact]
    public async Task LinesLongerThanTheReadBufferArePutTogether()
    {
        var long1 = new string('a', 40_000);
        var reader = Reader(long1 + "\nb\n", max: 100_000);
        Assert.Equal(long1, await reader.ReadLineAsync(TestContext.Current.CancellationToken));
        Assert.Equal("b", await reader.ReadLineAsync(TestContext.Current.CancellationToken));
    }
}

public class ApprovalTests
{
    [Fact]
    public void TheChangeIsSaidInPlainWords()
    {
        Assert.Equal(@"Allow C:\Tools\a.exe.", ApprovalText.Describe(new ApiRequest { Op = ApiOps.SetRule, App = @"C:\Tools\a.exe", Action = "allow" }));
        Assert.Equal(@"Block C:\a.exe (incoming) for 60 minutes.", ApprovalText.Describe(new ApiRequest { Op = ApiOps.SetRule, App = @"C:\a.exe", Action = "block", Direction = "in", ExpiresMinutes = 60 }));
        Assert.Contains("OFF", ApprovalText.Describe(new ApiRequest { Op = ApiOps.SetProtection, Enabled = false }), StringComparison.Ordinal);
        Assert.Equal("Delete every CrioFire rule.", ApprovalText.Describe(new ApiRequest { Op = ApiOps.Panic, Action = "remove" }));
        Assert.Equal("Stop the CrioFire service.", ApprovalText.Describe(new ApiRequest { Op = ApiOps.StopService }));
    }

    [Fact]
    public void WhatIsShownCannotBeDressedUp()
    {
        // A right-to-left mark would show "exe.gpj" as "jpg.exe"; line breaks could push text out of sight.
        var text = ApprovalText.Describe(new ApiRequest { Op = ApiOps.SetRule, App = "C:\\a\u202Egpj.exe\n\nAllow something harmless", Action = "allow" });
        Assert.DoesNotContain('\u202E', text);
        Assert.DoesNotContain('\n', text);
    }

    [Theory]
    [InlineData(@"C:\Users\x\AppData\Local\Temp\criofire-approval-0123456789abcdef0123456789abcdef.json", true)]
    [InlineData(@"C:\Windows\System32\drivers\etc\hosts", false)]
    [InlineData(@"C:\Temp\criofire-approval-0123456789ABCDEF0123456789abcdef.json", false)]
    [InlineData(@"C:\Temp\criofire-approval-short.json", false)]
    [InlineData(null, false)]
    public void TheAnswerGoesOnlyToTheAppsOwnKindOfFile(string? path, bool expected) =>
        Assert.Equal(expected, ApprovalPrompt.IsAnswerFile(path));
}

public class LocalPathTests
{
    [Theory]
    [InlineData(@"\\server\share\tool.exe", true)]
    [InlineData(@"//server/share/tool.exe", true)]
    [InlineData(@"\\?\UNC\server\share\tool.exe", true)]
    [InlineData(@"\\.\pipe\x", true)]
    [InlineData("\"\\\\server\\share\\tool.exe\"", true)]
    [InlineData(@"C:\Program Files\App\app.exe", false)]
    [InlineData("System", false)]
    [InlineData(null, false)]
    public void PathsOnOtherComputersAreRecognized(string? path, bool expected) =>
        Assert.Equal(expected, KnownApps.IsNetworkPath(path));

    [Fact]
    public void ARulesFileCannotNameAProgramOnAShare()
    {
        var set = new RuleSet { Programs = [new AppRuleEntry(@"\\evil\share\x.exe", "allow", "out")] };
        Assert.NotNull(RuleBackup.Validate(set));
        Assert.Null(NetRule.Create(RuleAction.Allow, TrafficDirection.Outbound, NetProtocol.Tcp, "443", null, @"\\evil\share\x.exe", out var error));
        Assert.Contains("network share", error, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("https://github.com/blackaivengo/CrioFire/releases/tag/v1.2.0", "https://github.com/blackaivengo/CrioFire/releases/tag/v1.2.0")]
    [InlineData("https://github.com.evil.example/x", UpdateCheck.ReleasesPage)]
    [InlineData("https://github.com@evil.example/x", UpdateCheck.ReleasesPage)]
    [InlineData(@"C:\Windows\System32\calc.exe", UpdateCheck.ReleasesPage)]
    [InlineData("file:///C:/x.exe", UpdateCheck.ReleasesPage)]
    [InlineData(null, UpdateCheck.ReleasesPage)]
    public void OnlyGitHubPagesAreOpened(string? url, string expected) =>
        Assert.Equal(expected, UpdateCheck.PageToOpen(url));
}
