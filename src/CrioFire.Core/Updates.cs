using System.Globalization;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace CrioFire.Core;

/// <summary>A published CrioFire release.</summary>
/// <param name="Version">Without the "v": 1.2.0.</param>
/// <param name="Url">The release page, with the notes and the installers.</param>
public sealed record UpdateRelease(string Version, string Url, DateTime? PublishedUtc);

/// <summary>What the last update check found.</summary>
/// <param name="Latest">The newest release; null when none is published yet (or the check failed).</param>
/// <param name="Error">Why the last check failed; null when it worked.</param>
public sealed record UpdateResult(DateTime CheckedUtc, UpdateRelease? Latest, string? Error);

/// <summary>The update check as the app and the command line see it.</summary>
/// <param name="Enabled">Checks once a day (the setting).</param>
/// <param name="TurnedOffByPolicy">An administrator turned the check off for this PC (group policy).</param>
/// <param name="Current">The version running here.</param>
/// <param name="Newer">The latest release is newer than this one.</param>
public sealed record UpdateState(bool Enabled, bool TurnedOffByPolicy, string Current, UpdateResult? Last, bool Newer);

/// <summary>
/// Looks for a newer CrioFire on GitHub Releases. The request carries nothing about the PC or its
/// rules, only what any web request does (address, "CrioFire/version" as the user agent). Nothing
/// is downloaded or installed: the app tells the user and links to the release page. The service
/// checks once a day (its own connections are always allowed, whatever the mode).
/// </summary>
public static class UpdateCheck
{
    public const string ReleasesApi = "https://api.github.com/repos/blackaivengo/CrioFire/releases/latest";
    public const string ReleasesPage = "https://github.com/blackaivengo/CrioFire/releases";

    /// <summary>Group policy: a DWORD of 1 here turns the check off for every user of the PC.</summary>
    public const string PolicyKey = @"SOFTWARE\Policies\CrioSoft\CrioFire";
    public const string PolicyValue = "DisableUpdateCheck";

    public static readonly TimeSpan Interval = TimeSpan.FromDays(1);

    private static readonly Lazy<HttpClient> Http = new(() =>
    {
        var http = new HttpClient { Timeout = TimeSpan.FromSeconds(20) };
        http.DefaultRequestHeaders.UserAgent.ParseAdd("CrioFire/" + CurrentVersion);
        http.DefaultRequestHeaders.Accept.ParseAdd("application/vnd.github+json");
        return http;
    });

    /// <summary>This build's version, as the assembly says (1.2.0, 0.1.0-dev).</summary>
    public static string CurrentVersion { get; } = Normalize(
        typeof(UpdateCheck).Assembly.GetCustomAttributes(typeof(System.Reflection.AssemblyInformationalVersionAttribute), false)
            .OfType<System.Reflection.AssemblyInformationalVersionAttribute>().FirstOrDefault()?.InformationalVersion ?? "0.0.0");

    /// <summary>"v1.2.0+abc123" → "1.2.0".</summary>
    public static string Normalize(string version)
    {
        ArgumentNullException.ThrowIfNull(version);
        var v = version.Trim();
        if (v.StartsWith('v') || v.StartsWith('V'))
        {
            v = v[1..];
        }

        var plus = v.IndexOf('+', StringComparison.Ordinal);
        return plus >= 0 ? v[..plus] : v;
    }

    /// <summary>
    /// <paramref name="latest"/> is a later version than <paramref name="current"/>: the numbers
    /// compare part by part; with the same numbers, a release is later than a preview of it
    /// (1.2.0 after 1.2.0-beta, and after this repository's dev and CI builds). Unreadable: false.
    /// </summary>
    public static bool IsNewer(string latest, string current)
    {
        if (Parse(latest) is not { } l || Parse(current) is not { } c)
        {
            return false;
        }

        for (var i = 0; i < 4; i++)
        {
            if (l.Numbers[i] != c.Numbers[i])
            {
                return l.Numbers[i] > c.Numbers[i];
            }
        }

        return l.Preview is null && c.Preview is not null;
    }

    /// <summary>The release in GitHub's answer for /releases/latest; null for a draft or a preview.</summary>
    public static UpdateRelease? ParseLatest(string json)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            var r = doc.RootElement;
            if (r.ValueKind != JsonValueKind.Object
                || r.TryGetProperty("draft", out var draft) && draft.ValueKind == JsonValueKind.True
                || r.TryGetProperty("prerelease", out var pre) && pre.ValueKind == JsonValueKind.True
                || !r.TryGetProperty("tag_name", out var tag) || tag.GetString() is not { Length: > 0 } tagName
                || Parse(Normalize(tagName)) is null)
            {
                return null;
            }

            var url = r.TryGetProperty("html_url", out var html) && html.GetString() is { } page
                && page.StartsWith("https://github.com/", StringComparison.OrdinalIgnoreCase)
                    ? page
                    : ReleasesPage;
            DateTime? published = r.TryGetProperty("published_at", out var at) && at.GetString() is { } text
                && DateTime.TryParse(text, CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out var time)
                    ? time
                    : null;
            return new UpdateRelease(Normalize(tagName), url, published);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    /// <summary>Asks GitHub for the latest release now. Never throws for network trouble: the result says what went wrong.</summary>
    public static UpdateResult Fetch(DateTime nowUtc, CancellationToken cancellationToken = default)
    {
        try
        {
            using var response = Http.Value.Send(new HttpRequestMessage(HttpMethod.Get, ReleasesApi), cancellationToken);
            if (response.StatusCode == HttpStatusCode.NotFound)
            {
                return new UpdateResult(nowUtc, null, null);   // no release published yet
            }

            if (!response.IsSuccessStatusCode)
            {
                return new UpdateResult(nowUtc, null, $"GitHub answered {(int)response.StatusCode} {response.ReasonPhrase}.");
            }

            using var reader = new StreamReader(response.Content.ReadAsStream(cancellationToken), Encoding.UTF8);
            var latest = ParseLatest(reader.ReadToEnd());
            return latest is null
                ? new UpdateResult(nowUtc, null, "GitHub's answer had no release in it.")
                : new UpdateResult(nowUtc, latest, null);
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or IOException)
        {
            return new UpdateResult(nowUtc, null, "Could not reach GitHub: " + ex.GetBaseException().Message);
        }
    }

    private static (int[] Numbers, string? Preview)? Parse(string version)
    {
        var v = Normalize(version);
        var dash = v.IndexOf('-', StringComparison.Ordinal);
        var preview = dash >= 0 ? v[(dash + 1)..] : null;
        var parts = (dash >= 0 ? v[..dash] : v).Split('.');
        if (parts.Length is < 1 or > 4)
        {
            return null;
        }

        var numbers = new int[4];
        for (var i = 0; i < parts.Length; i++)
        {
            if (!int.TryParse(parts[i], NumberStyles.None, CultureInfo.InvariantCulture, out numbers[i]))
            {
                return null;
            }
        }

        return (numbers, preview);
    }
}

/// <summary>
/// The update check's setting (update-check.txt: on or off; on when missing) and its last result
/// (update.json), in %ProgramData%\criofire. Group policy can turn it off for the whole PC.
/// </summary>
public sealed class UpdateStore(string folder)
{
    public static string DefaultFolder => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "criofire");

    public string SettingPath => Path.Combine(folder, "update-check.txt");

    public string ResultPath => Path.Combine(folder, "update.json");

    /// <summary>For tests: stands in for the group policy.</summary>
    public Func<bool>? PolicyOverride { get; init; }

    public bool TurnedOffByPolicy => PolicyOverride?.Invoke() ?? ReadPolicy();

    public bool Enabled
    {
        get
        {
            try
            {
                return !File.Exists(SettingPath) || LogSettings.ParseSwitch(File.ReadAllText(SettingPath)) != false;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                return true;
            }
        }
    }

    public void SetEnabled(bool enabled)
    {
        Directory.CreateDirectory(folder);
        File.WriteAllText(SettingPath, enabled ? "on\n" : "off\n");
    }

    public UpdateResult? Last()
    {
        try
        {
            return File.Exists(ResultPath) ? JsonSerializer.Deserialize(File.ReadAllText(ResultPath), UpdateJson.Default.UpdateResult) : null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        {
            return null;
        }
    }

    public void Save(UpdateResult result)
    {
        ArgumentNullException.ThrowIfNull(result);
        Directory.CreateDirectory(folder);
        File.WriteAllText(ResultPath + ".tmp", JsonSerializer.Serialize(result, UpdateJson.Default.UpdateResult));
        File.Move(ResultPath + ".tmp", ResultPath, overwrite: true);
    }

    /// <summary>The state for the app: setting, policy, this version and what the last check found.</summary>
    public UpdateState State(string current)
    {
        var last = Last();
        return new UpdateState(Enabled, TurnedOffByPolicy, current, last, last?.Latest is { } latest && UpdateCheck.IsNewer(latest.Version, current));
    }

    /// <summary>The check is on and its last run is a day old (or never happened, or the last attempt failed an hour ago).</summary>
    public bool Due(DateTime nowUtc)
    {
        if (!Enabled || TurnedOffByPolicy)
        {
            return false;
        }

        return Last() is not { } last
            || nowUtc - last.CheckedUtc >= UpdateCheck.Interval
            || (last.Error is not null && nowUtc - last.CheckedUtc >= TimeSpan.FromHours(1))
            || last.CheckedUtc > nowUtc + TimeSpan.FromHours(1);   // the clock went back
    }

    private static bool ReadPolicy()
    {
        if (!OperatingSystem.IsWindows())
        {
            return false;
        }

        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(UpdateCheck.PolicyKey);
            return key?.GetValue(UpdateCheck.PolicyValue) is int value && value != 0;
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException or IOException)
        {
            return false;
        }
    }
}

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(UpdateResult))]
internal sealed partial class UpdateJson : JsonSerializerContext;
