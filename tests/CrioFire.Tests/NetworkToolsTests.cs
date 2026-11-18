using CrioFire.Core;

namespace CrioFire.Tests;

public class NetworkToolsTests
{
    [Theory]
    [InlineData("203.0.113.5", "203.0.113.5")]
    [InlineData(" 10.0.0.1 ", "10.0.0.1")]
    [InlineData("2001:db8::1", "2001:db8::1")]
    [InlineData("[2001:db8::1]", "2001:db8::1")]
    [InlineData("2001:0db8:0000::0001", "2001:db8::1")]
    public void AcceptsOnlyIpAddresses(string text, string expected) => Assert.Equal(expected, NetworkTools.Address(text));

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("example.com")]
    [InlineData("10.0.0.1 & calc")]
    [InlineData("10.0.0.1\" -t")]
    [InlineData("fe80::1%12")]
    [InlineData("1.2.3.4:443")]
    public void RejectsAnythingElse(string? text) => Assert.Null(NetworkTools.Address(text));

    [Fact]
    public void BuildsTheChecks()
    {
        Assert.Equal(new ToolCommand("ping.exe", "-n 4 203.0.113.5"), NetworkTools.Ping("203.0.113.5"));
        Assert.Equal(new ToolCommand("tracert.exe", "-h 30 -w 1000 2001:db8::1"), NetworkTools.TraceRoute("[2001:db8::1]"));
        Assert.Equal(new ToolCommand("nslookup.exe", "203.0.113.5"), NetworkTools.NameLookup("203.0.113.5"));
        Assert.Throws<ArgumentException>(() => NetworkTools.Ping("example.com & calc"));
    }

    [Fact]
    public void BuildsTheTerminals()
    {
        Assert.Equal("203.0.113.5", NetworkTools.Ssh("203.0.113.5").Arguments);
        Assert.Equal("-p 2222 203.0.113.5", NetworkTools.Ssh("203.0.113.5", 2222).Arguments);
        Assert.Equal("/v:203.0.113.5", NetworkTools.RemoteDesktop("203.0.113.5").Arguments);
        Assert.Equal("/v:[2001:db8::1]:3390", NetworkTools.RemoteDesktop("2001:db8::1", 3390).Arguments);
        Assert.Equal("203.0.113.5 23", NetworkTools.Telnet("203.0.113.5", 23).Arguments);
        Assert.Contains("Test-NetConnection -ComputerName 203.0.113.5 -Port 443", NetworkTools.PowerShellTest("203.0.113.5", 443).Arguments, StringComparison.Ordinal);
        Assert.Throws<ArgumentOutOfRangeException>(() => NetworkTools.Telnet("203.0.113.5", 70000));
    }

    [Fact]
    public void KeepsTheNetstatLinesAboutTheAddress()
    {
        string[] netstat =
        [
            "",
            "Active Connections",
            "",
            "  Proto  Local Address          Foreign Address        State           PID",
            "  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       1100",
            "  TCP    192.168.1.20:50312     203.0.113.5:443        ESTABLISHED     4242",
            "  TCP    192.168.1.20:50313     203.0.113.50:443       ESTABLISHED     4243",
            "  TCP    [2001:db8::20]:50400   [2001:db8::1]:22       TIME_WAIT       0",
            "  UDP    0.0.0.0:5353           *:*                                    2000",
        ];

        var lines = NetworkTools.ConnectionsWith(netstat, "203.0.113.5", pid => pid == 4242 ? "chat.exe" : null);
        Assert.Equal(2, lines.Count);
        Assert.StartsWith("  Proto", lines[0], StringComparison.Ordinal);
        Assert.EndsWith("4242  chat.exe", lines[1], StringComparison.Ordinal);

        var v6 = NetworkTools.ConnectionsWith(netstat, "2001:db8::1");
        Assert.Equal(2, v6.Count);
        Assert.Contains("[2001:db8::1]:22", v6[1], StringComparison.Ordinal);

        Assert.Empty(NetworkTools.ConnectionsWith(netstat, "198.51.100.7"));
    }

    [Fact]
    public void LinksToTheWeb()
    {
        Assert.Equal("https://www.google.com/search?q=%22chat.exe%22%20Chat%20Contoso", NetworkTools.SearchUrl("chat.exe", "Chat", "Contoso"));
        Assert.Equal("https://www.google.com/search?q=%22chat.exe%22", NetworkTools.SearchUrl("chat.exe", "chat.exe", " "));
        Assert.Equal("https://www.virustotal.com/gui/file/abcdef", NetworkTools.VirusTotalUrl("ABCDEF"));
        Assert.Equal("https://ipinfo.io/203.0.113.5", NetworkTools.OwnerUrl("203.0.113.5"));
    }

    [Theory]
    [InlineData(0, SignatureState.Valid)]
    [InlineData(unchecked((int)0x800B0100), SignatureState.NotSigned)]
    [InlineData(unchecked((int)0x800B0003), SignatureState.NotSigned)]
    [InlineData(unchecked((int)0x80096010), SignatureState.Tampered)]
    [InlineData(unchecked((int)0x800B0101), SignatureState.Expired)]
    [InlineData(unchecked((int)0x800B010C), SignatureState.Revoked)]
    [InlineData(unchecked((int)0x800B0109), SignatureState.UntrustedRoot)]
    [InlineData(unchecked((int)0x800B0111), SignatureState.Distrusted)]
    [InlineData(unchecked((int)0x80004005), SignatureState.Invalid)]
    public void ReadsWinVerifyTrustResults(int result, SignatureState expected) => Assert.Equal(expected, SignatureInfo.StateOf(result));
}
