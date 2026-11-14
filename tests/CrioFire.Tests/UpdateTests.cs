using CrioFire.Cli;
using CrioFire.Core;
using CrioFire.Core.Api;

namespace CrioFire.Tests;

/// <summary>The update check: versions, GitHub's answer, the setting and result files, the API and the command line.</summary>
public sealed class UpdateTests : IDisposable
{
    private static readonly DateTime Now = new(2026, 11, 13, 12, 0, 0, DateTimeKind.Utc);

    private readonly string _dir = Path.Combine(Path.GetTempPath(), "criofire-update-" + Guid.NewGuid().ToString("N"));

    public void Dispose()
    {
        if (Directory.Exists(_dir))
        {
            Directory.Delete(_dir, recursive: true);
        }
    }

    [Theory]
    [InlineData("v1.2.0", "1.2.0")]
    [InlineData("1.2.0+abc123", "1.2.0")]
    [InlineData(" V2.0.0-beta.1+sha ", "2.0.0-beta.1")]
    public void VersionsAreNormalized(string raw, string normal) => Assert.Equal(normal, UpdateCheck.Normalize(raw));

    [Theory]
    [InlineData("1.2.1", "1.2.0", true)]
    [InlineData("1.10.0", "1.9.9", true)]
    [InlineData("2.0.0", "1.99.99", true)]
    [InlineData("1.2.0", "1.2.0", false)]
    [InlineData("1.2.0", "1.2.1", false)]
    [InlineData("1.2.0", "1.2.0-beta", true)]       // the release after its preview
    [InlineData("0.1.0", "0.1.0-dev", true)]        // after a developer build
    [InlineData("0.1.0", "0.0.0-ci.64", true)]      // after a CI build
    [InlineData("1.2.0-beta", "1.2.0", false)]
    [InlineData("v1.3", "1.2.9", true)]
    [InlineData("1.2.0.1", "1.2.0", true)]
    [InlineData("latest", "1.2.0", false)]
    [InlineData("1.2.0", "unknown", false)]
    public void NewerMeansALaterVersion(string latest, string current, bool newer) =>
        Assert.Equal(newer, UpdateCheck.IsNewer(latest, current));

    [Fact]
    public void GitHubsLatestReleaseIsRead()
    {
        var release = UpdateCheck.ParseLatest("""
            {"tag_name":"v1.4.0","name":"CrioFire 1.4","draft":false,"prerelease":false,
             "html_url":"https://github.com/blackaivengo/CrioFire/releases/tag/v1.4.0","published_at":"2026-11-10T09:30:00Z"}
            """);

        Assert.NotNull(release);
        Assert.Equal("1.4.0", release.Version);
        Assert.Equal("https://github.com/blackaivengo/CrioFire/releases/tag/v1.4.0", release.Url);
        Assert.Equal(new DateTime(2026, 11, 10, 9, 30, 0, DateTimeKind.Utc), release.PublishedUtc);
    }

    [Theory]
    [InlineData("""{"tag_name":"v1.4.0","draft":true}""")]
    [InlineData("""{"tag_name":"v1.4.0","prerelease":true}""")]
    [InlineData("""{"tag_name":"nightly"}""")]
    [InlineData("""{"message":"Not Found"}""")]
    [InlineData("[]")]
    [InlineData("not json")]
    public void DraftsPreviewsAndOddAnswersAreNotReleases(string json) => Assert.Null(UpdateCheck.ParseLatest(json));

    [Fact]
    public void OnlyGitHubPagesAreLinked()
    {
        var release = UpdateCheck.ParseLatest("""{"tag_name":"v1.4.0","html_url":"https://example.com/fake"}""");
        Assert.Equal(UpdateCheck.ReleasesPage, release?.Url);
    }

    [Fact]
    public void TheCheckIsOnUntilTurnedOff()
    {
        var store = Store();
        Assert.True(store.Enabled);
        store.SetEnabled(false);
        Assert.False(store.Enabled);
        Assert.False(store.Due(Now));
        store.SetEnabled(true);
        Assert.True(store.Enabled);
    }

    [Fact]
    public void ADailyCheckIsDueOnceADayAndSoonerAfterAFailure()
    {
        var store = Store();
        Assert.True(store.Due(Now));   // never checked

        store.Save(new UpdateResult(Now, new UpdateRelease("1.0.0", UpdateCheck.ReleasesPage, null), null));
        Assert.False(store.Due(Now.AddHours(23)));
        Assert.True(store.Due(Now.AddHours(24)));

        store.Save(new UpdateResult(Now, null, "Could not reach GitHub."));
        Assert.False(store.Due(Now.AddMinutes(30)));
        Assert.True(store.Due(Now.AddHours(1)));

        store.Save(new UpdateResult(Now.AddDays(3), null, null));
        Assert.True(store.Due(Now));   // the clock went back
    }

    [Fact]
    public void GroupPolicyTurnsTheDailyCheckOff()
    {
        var store = Store(policy: true);
        Assert.True(store.Enabled);
        Assert.True(store.TurnedOffByPolicy);
        Assert.False(store.Due(Now));
        Assert.True(store.State("1.0.0").TurnedOffByPolicy);
    }

    [Fact]
    public void TheStateSaysWhetherTheLatestIsNewer()
    {
        var store = Store();
        Assert.Null(store.State("1.0.0").Last);

        store.Save(new UpdateResult(Now, new UpdateRelease("1.1.0", UpdateCheck.ReleasesPage, Now), null));
        Assert.Equal("1.1.0", store.Last()?.Latest?.Version);
        Assert.True(store.State("1.0.0").Newer);
        Assert.False(store.State("1.1.0").Newer);
        Assert.False(store.State("1.2.0").Newer);

        File.WriteAllText(store.ResultPath, "{broken");
        Assert.Null(store.Last());
    }

    [Fact]
    public void TheApiShowsAndChangesTheSetting()
    {
        var store = Store();
        store.Save(new UpdateResult(Now, new UpdateRelease("99.0.0", UpdateCheck.ReleasesPage, Now), null));
        var handler = new ApiHandler(null!, updates: store);

        var state = handler.Handle(new ApiRequest { Op = ApiOps.Update }, ClientRights.ReadOnly).Update!;
        Assert.True(state.Enabled);
        Assert.True(state.Newer);
        Assert.Equal(UpdateCheck.CurrentVersion, state.Current);

        Assert.False(handler.Handle(new ApiRequest { Op = ApiOps.CheckUpdate }, ClientRights.ReadOnly).Ok);
        Assert.False(handler.Handle(new ApiRequest { Op = ApiOps.SetUpdateCheck, Enabled = false }, ClientRights.ReadOnly).Ok);
        Assert.False(handler.Handle(new ApiRequest { Op = ApiOps.SetUpdateCheck }, ClientRights.Administrator).Ok);

        Assert.False(handler.Handle(new ApiRequest { Op = ApiOps.SetUpdateCheck, Enabled = false }, ClientRights.Administrator).Update!.Enabled);
        Assert.False(store.Enabled);
        Assert.False(new ApiHandler(null!).Handle(new ApiRequest { Op = ApiOps.Update }, ClientRights.ReadOnly).Ok);
    }

    [Fact]
    public void TheCommandLineChecksAndSwitches()
    {
        Assert.False(CommandLine.Parse(["version"], out _).All);
        var check = CommandLine.Parse(["version", "--check"], out var error);
        Assert.Null(error);
        Assert.Equal(CommandKind.Version, check.Kind);
        Assert.True(check.All);

        var off = CommandLine.Parse(["updates", "off"], out error);
        Assert.Null(error);
        Assert.Equal(CommandKind.Updates, off.Kind);
        Assert.False(off.Enabled);
        Assert.True(CommandLine.Parse(["updates", "on"], out _).Enabled);

        Assert.Equal(CommandKind.Help, CommandLine.Parse(["updates"], out error).Kind);
        Assert.NotNull(error);
        Assert.Equal(CommandKind.Help, CommandLine.Parse(["version", "--now"], out _).Kind);
    }

    [Fact]
    public void TheAppRemembersWhichVersionItWasToldAbout()
    {
        var prefs = UiPreferences.Parse("theme=dark\n");
        Assert.Null(prefs.DismissedUpdate);
        prefs.DismissedUpdate = "1.4.0";
        prefs.AnnouncedUpdate = "1.4.0";

        var back = UiPreferences.Parse(prefs.Format());
        Assert.Equal("1.4.0", back.DismissedUpdate);
        Assert.Equal("1.4.0", back.AnnouncedUpdate);
        Assert.Equal("dark", back.Theme);

        back.DismissedUpdate = null;
        Assert.DoesNotContain("dismissedUpdate", back.Format(), StringComparison.Ordinal);
    }

    private UpdateStore Store(bool policy = false) => new(_dir) { PolicyOverride = () => policy };
}
