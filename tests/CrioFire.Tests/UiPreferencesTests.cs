using CrioFire.Core;

namespace CrioFire.Tests;

public class UiPreferencesTests
{
    [Fact]
    public void DefaultsWhenEmpty()
    {
        var p = UiPreferences.Parse(string.Empty);
        Assert.Equal("system", p.Theme);
        Assert.True(p.CloseToTray);
        Assert.False(p.TrayHintShown);
        Assert.False(p.AutostartAsked);
    }

    [Fact]
    public void ReadsTheFirstVersionsThemeOnlyFile()
    {
        Assert.Equal("dark", UiPreferences.Parse("dark\n").Theme);
        Assert.Equal("light", UiPreferences.Parse("  light ").Theme);
        Assert.Equal("system", UiPreferences.Parse("purple").Theme);
    }

    [Fact]
    public void RoundTripsAndKeepsUnknownKeys()
    {
        var p = UiPreferences.Parse("future=42\r\ntheme=light\n");
        p.CloseToTray = false;
        p.TrayHintShown = true;
        var back = UiPreferences.Parse(p.Format());
        Assert.Equal("light", back.Theme);
        Assert.False(back.CloseToTray);
        Assert.True(back.TrayHintShown);
        Assert.Contains("future=42", back.Format());
    }

    [Fact]
    public void BadValuesFallBackToDefaults()
    {
        var p = UiPreferences.Parse("closeToTray=maybe\ntrayHintShown=\n=x\n");
        Assert.True(p.CloseToTray);
        Assert.False(p.TrayHintShown);
    }

    [Fact]
    public void SavesAndLoads()
    {
        var path = Path.Combine(Path.GetTempPath(), $"criofire-ui-{Guid.NewGuid():N}", "ui.txt");
        try
        {
            var p = new UiPreferences { Theme = "dark", AutostartAsked = true };
            Assert.True(p.Save(path));
            var back = UiPreferences.Load(path);
            Assert.Equal("dark", back.Theme);
            Assert.True(back.AutostartAsked);
            Assert.Equal("system", UiPreferences.Load(path + ".missing").Theme);
        }
        finally
        {
            Directory.Delete(Path.GetDirectoryName(path)!, recursive: true);
        }
    }
}

public class AutostartCommandTests
{
    private static readonly string Exe = Path.GetFullPath(Path.Combine(Path.GetTempPath(), "CrioFire", "criofire-ui.exe"));

    [Fact]
    public void QuotesThePathAndStartsInTheTray() =>
        Assert.Equal($"\"{Exe}\" --tray", AutostartCommand.For(Exe));

    [Fact]
    public void MachineEntryIsMarked()
    {
        Assert.Equal($"\"{Exe}\" --tray --machine", AutostartCommand.ForMachine(Exe));
        Assert.True(AutostartCommand.Points(AutostartCommand.ForMachine(Exe), Exe));
    }

    [Fact]
    public void RemembersOptingOutOfTheMachineWideStart()
    {
        var p = UiPreferences.Parse(string.Empty);
        Assert.False(p.AutostartOff);
        p.AutostartOff = true;
        Assert.True(UiPreferences.Parse(p.Format()).AutostartOff);
    }

    [Fact]
    public void RecognizesItsOwnRunValue()
    {
        Assert.True(AutostartCommand.Points(AutostartCommand.For(Exe), Exe));
        Assert.True(AutostartCommand.Points($"\"{Exe.ToUpperInvariant()}\"", Exe));
        Assert.False(AutostartCommand.Points("\"C:\\Other\\app.exe\" --tray", Exe));
        Assert.False(AutostartCommand.Points(null, Exe));
        Assert.False(AutostartCommand.Points("  ", Exe));
    }
}
