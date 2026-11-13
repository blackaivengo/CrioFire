using System.Net.Http.Json;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace CrioFire.Core.Management;

// The protocol between a PC running CrioFire (the agent: the criofire service) and a company's
// CrioFire Server. PCs enroll once with a code from the admin, then check in every few minutes
// (5 by default, set by the server) with a small state report: no connection data. What a PC
// blocked and allowed is sent only when an administrator asks for it, for that one PC, so a
// network of many PCs never floods the server.

public sealed record EnrollRequest(string Token, string Computer, string? OsVersion, string? AppVersion);

public sealed record EnrollResponse(string DeviceId, string Secret, string ServerName);

/// <summary>What a PC reports at every check-in: its state only, a few hundred bytes.</summary>
public sealed record CheckinReport
{
    public string Computer { get; init; } = string.Empty;

    public string? AppVersion { get; init; }

    public string? OsVersion { get; init; }

    public bool Installed { get; init; }

    public string Mode { get; init; } = "learning";

    public string Panic { get; init; } = "off";

    public int ProgramRules { get; init; }

    public int NetworkRules { get; init; }

    public int ServiceRules { get; init; }

    public int ChangedPrograms { get; init; }

    public bool RequireAdmin { get; init; }

    public string License { get; init; } = "none";

    /// <summary>The id of the license this PC has (null: none), so the server sends its key only when it differs.</summary>
    public string? LicenseId { get; init; }

    /// <summary>The policy this PC has applied (null: none) and its version.</summary>
    public string? PolicyId { get; init; }

    public int PolicyVersion { get; init; }
}

/// <param name="NextCheckinSeconds">When to check in next; the server decides (default 300).</param>
/// <param name="Activity">An administrator asked for this PC's connections: send them (POST api/v1/activity).</param>
/// <param name="PolicyId">The policy assigned to this PC, or null for none (the PC then removes organization rules).</param>
/// <param name="Policy">The whole policy, sent only when the PC reported another policy or version.</param>
/// <param name="LicenseKey">The organization's license key, sent only when the PC reported another license.</param>
public sealed record CheckinResponse(
    int PolicyVersion,
    DateTime ServerTimeUtc,
    int NextCheckinSeconds = ServerDefaults.CheckinSeconds,
    ActivityRequest? Activity = null,
    string? PolicyId = null,
    ManagedPolicy? Policy = null,
    string? LicenseKey = null);

/// <summary>An administrator's request for one PC's connections.</summary>
/// <param name="Kind">blocked, allowed or all.</param>
/// <param name="Hours">How far back (1 to 720).</param>
/// <param name="Limit">At most this many rows (grouped by program, destination and reason; up to 500).</param>
public sealed record ActivityRequest(string RequestId, string Kind, int Hours, int Limit, DateTime RequestedUtc);

/// <summary>The PC's answer to an <see cref="ActivityRequest"/>.</summary>
public sealed record ActivityUpload(string RequestId, DateTime CreatedUtc, TrafficPage Page);

/// <summary>This PC's link to a CrioFire Server: %ProgramData%\criofire\server.json (administrators and the service only).</summary>
/// <param name="Fingerprint">SHA-256 of the server's certificate, when it is pinned (the server's own self-signed certificate).</param>
public sealed record ServerLink(string Url, string DeviceId, string Secret, string? Fingerprint, DateTime EnrolledUtc)
{
    public DateTime? LastCheckinUtc { get; init; }

    public string? LastError { get; init; }

    public string? PolicyId { get; init; }

    public int PolicyVersion { get; init; }
}

/// <summary>What the app and the command line may know about the link: everything but the secret.</summary>
/// <param name="Policy">The organization's policy in force, if any (name, mode, whether the user may add rules).</param>
public sealed record ManagementInfo(string Url, string DeviceId, DateTime EnrolledUtc, DateTime? LastCheckinUtc, string? LastError, int PolicyVersion, PolicySummary? Policy = null)
{
    public static ManagementInfo From(ServerLink link, ManagedPolicy? policy = null)
    {
        ArgumentNullException.ThrowIfNull(link);
        return new(link.Url, link.DeviceId, link.EnrolledUtc, link.LastCheckinUtc, link.LastError, link.PolicyVersion,
            policy is null ? null : new PolicySummary(policy.Name, policy.Mode, policy.AllowUserRules, policy.RequireAdmin, policy.Rules.Count, policy.UpdatedUtc));
    }
}

public sealed record PolicySummary(string Name, string? Mode, bool AllowUserRules, bool RequireAdmin, int Rules, DateTime UpdatedUtc);

public sealed class ServerLinkStore(string path)
{
    private static readonly Lock Gate = new();

    public static string DefaultPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "criofire", "server.json");

    public string FilePath { get; } = path;

    public ServerLink? Load()
    {
        lock (Gate)
        {
            try
            {
                return File.Exists(FilePath) ? JsonSerializer.Deserialize(File.ReadAllText(FilePath), ManagementJson.Default.ServerLink) : null;
            }
            catch (JsonException)
            {
                return null;
            }
        }
    }

    public void Save(ServerLink link)
    {
        ArgumentNullException.ThrowIfNull(link);
        lock (Gate)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(FilePath))!);
            var temp = FilePath + ".tmp";
            File.WriteAllText(temp, JsonSerializer.Serialize(link, ManagementJson.Default.ServerLink));
            RestrictToAdministrators(temp);
            File.Move(temp, FilePath, overwrite: true);
        }
    }

    /// <summary>The file holds this PC's secret for the server: only SYSTEM and administrators may read it.</summary>
    private static void RestrictToAdministrators(string path)
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        var security = new FileSecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), FileSystemRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), FileSystemRights.FullControl, AccessControlType.Allow));
        new FileInfo(path).SetAccessControl(security);
    }

    public void Delete()
    {
        lock (Gate)
        {
            File.Delete(FilePath);
        }
    }
}

/// <summary>Talks to a CrioFire Server over HTTPS, checking its certificate against the pinned fingerprint when there is one.</summary>
public sealed class ManagementClient : IDisposable
{
    public const string DeviceScheme = "Device";

    private readonly HttpClient _http;

    public ManagementClient(string url, string? fingerprint, TimeSpan? timeout = null)
    {
        var handler = new HttpClientHandler
        {
            ServerCertificateCustomValidationCallback = (_, certificate, _, errors) =>
                fingerprint is { Length: > 0 }
                    ? certificate is not null && Fingerprints.Matches(Fingerprints.Of(certificate), fingerprint)
                    : errors == SslPolicyErrors.None,
        };
        _http = new HttpClient(handler) { BaseAddress = new Uri(NormalizeUrl(url)), Timeout = timeout ?? TimeSpan.FromSeconds(20) };
    }

    /// <summary>"fw.contoso.local" or "https://fw.contoso.local:7443/" → "https://fw.contoso.local:7443/".</summary>
    public static string NormalizeUrl(string url)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(url);
        var text = url.Trim();
        if (!text.Contains("://", StringComparison.Ordinal))
        {
            text = "https://" + text;
        }

        var uri = new Uri(text);
        if (uri.Scheme != Uri.UriSchemeHttps)
        {
            throw new ArgumentException("The CrioFire Server address must use https.");
        }

        var port = HasExplicitPort(text) ? uri.Port : ServerDefaults.Port;
        return $"https://{uri.Host}:{port}/";
    }

    public async Task<EnrollResponse> EnrollAsync(EnrollRequest request, CancellationToken cancellationToken = default)
    {
        using var response = await _http.PostAsJsonAsync("api/v1/enroll", request, ManagementJson.Default.EnrollRequest, cancellationToken).ConfigureAwait(false);
        await ThrowIfFailed(response, cancellationToken).ConfigureAwait(false);
        return await response.Content.ReadFromJsonAsync(ManagementJson.Default.EnrollResponse, cancellationToken).ConfigureAwait(false)
            ?? throw new HttpRequestException("The server sent an empty answer.");
    }

    public async Task<CheckinResponse> CheckinAsync(ServerLink link, CheckinReport report, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(link);
        using var request = new HttpRequestMessage(HttpMethod.Post, "api/v1/checkin")
        {
            Content = JsonContent.Create(report, ManagementJson.Default.CheckinReport),
        };
        Authorize(request, link);
        using var response = await _http.SendAsync(request, cancellationToken).ConfigureAwait(false);
        await ThrowIfFailed(response, cancellationToken).ConfigureAwait(false);
        return await response.Content.ReadFromJsonAsync(ManagementJson.Default.CheckinResponse, cancellationToken).ConfigureAwait(false)
            ?? throw new HttpRequestException("The server sent an empty answer.");
    }

    /// <summary>Sends the connections an administrator asked for. The server refuses uploads nobody asked for.</summary>
    public async Task UploadActivityAsync(ServerLink link, ActivityUpload upload, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(link);
        using var request = new HttpRequestMessage(HttpMethod.Post, "api/v1/activity")
        {
            Content = JsonContent.Create(upload, ManagementJson.Default.ActivityUpload),
        };
        Authorize(request, link);
        using var response = await _http.SendAsync(request, cancellationToken).ConfigureAwait(false);
        await ThrowIfFailed(response, cancellationToken).ConfigureAwait(false);
    }

    private static void Authorize(HttpRequestMessage request, ServerLink link) =>
        request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue(DeviceScheme, $"{link.DeviceId}.{link.Secret}");

    public void Dispose() => _http.Dispose();

    private static bool HasExplicitPort(string text)
    {
        var afterScheme = text[(text.IndexOf("://", StringComparison.Ordinal) + 3)..];
        var host = afterScheme.Split('/', 2)[0];
        return host.StartsWith('[') ? host.Contains("]:", StringComparison.Ordinal) : host.Contains(':', StringComparison.Ordinal);
    }

    private static async Task ThrowIfFailed(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        if (response.IsSuccessStatusCode)
        {
            return;
        }

        var text = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        throw new HttpRequestException(string.IsNullOrWhiteSpace(text) ? $"The server answered {(int)response.StatusCode}." : text.Trim('"'), null, response.StatusCode);
    }
}

public static class ServerDefaults
{
    /// <summary>The HTTPS port CrioFire Server listens on unless configured otherwise.</summary>
    public const int Port = 7443;

    /// <summary>How often a PC checks in unless the server says otherwise: every 5 minutes.</summary>
    public const int CheckinSeconds = 300;

    public const int MinCheckinSeconds = 30;

    public const int MaxCheckinSeconds = 3600;

    /// <summary>The interval a server asked for, kept within sensible bounds.</summary>
    public static TimeSpan CheckinInterval(int seconds) =>
        TimeSpan.FromSeconds(Math.Clamp(seconds, MinCheckinSeconds, MaxCheckinSeconds));
}

/// <summary>Certificate fingerprints as people read them: SHA-256, hex in pairs ("AB:12:...").</summary>
public static class Fingerprints
{
    public static string Of(X509Certificate certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        var hex = Convert.ToHexString(SHA256.HashData(certificate.GetRawCertData()));
        return string.Join(':', Enumerable.Range(0, hex.Length / 2).Select(i => hex.Substring(i * 2, 2)));
    }

    public static bool Matches(string a, string b) =>
        string.Equals(Clean(a), Clean(b), StringComparison.OrdinalIgnoreCase);

    private static string Clean(string text) => new(text.Where(Uri.IsHexDigit).ToArray());
}

/// <summary>Builds the check-in report from what this PC knows.</summary>
public static class CheckinReports
{
    public static CheckinReport Build(
        WfpEngine engine,
        int changedPrograms,
        bool requireAdmin,
        string license,
        string? policyId,
        int policyVersion,
        string? licenseId = null)
    {
        ArgumentNullException.ThrowIfNull(engine);
        var installed = engine.IsInstalled();
        var rules = installed ? RuleBackup.Export(engine, null, DateTime.UtcNow) : new RuleSet();
        return new CheckinReport
        {
            Computer = Environment.MachineName,
            AppVersion = typeof(CheckinReports).Assembly.GetName().Version?.ToString(),
            OsVersion = Environment.OSVersion.VersionString,
            Installed = installed,
            Mode = rules.Mode ?? "learning",
            Panic = FilterDescriptions.PanicText(installed ? engine.GetPanic() : PanicState.Off),
            ProgramRules = rules.Programs.Count,
            NetworkRules = rules.Network.Count,
            ServiceRules = rules.Services.Count,
            ChangedPrograms = changedPrograms,
            RequireAdmin = requireAdmin,
            License = license,
            LicenseId = licenseId,
            PolicyId = policyId,
            PolicyVersion = policyVersion,
        };
    }

    /// <summary>
    /// Takes the organization's license key the server sent: only a valid key signed by CrioSoft,
    /// and only when this PC does not have that license yet. True when the key was saved.
    /// </summary>
    public static bool AcceptLicense(string? key, LicenseStore store, ECDsa? publicKey, DateTime nowUtc)
    {
        ArgumentNullException.ThrowIfNull(store);
        var offered = LicenseKeys.Check(key, nowUtc, publicKey);
        if (!offered.IsLicensed || LicenseKeys.Check(store.Key, nowUtc, publicKey).LicenseId == offered.LicenseId)
        {
            return false;
        }

        store.Set(key);
        return true;
    }

    /// <summary>The connections an administrator asked for, from this PC's own logs, grouped and most frequent first.</summary>
    public static ActivityUpload Activity(ActivityRequest request, TrafficLog? blockedLog, TrafficLog? allowedLog, DateTime nowUtc)
    {
        ArgumentNullException.ThrowIfNull(request);
        var kind = request.Kind is "blocked" or "allowed" ? request.Kind : "all";
        var from = nowUtc.AddHours(-Math.Clamp(request.Hours, 1, 720));
        var logs = new List<TrafficLog?>();
        if (kind != "allowed")
        {
            logs.Add(blockedLog);
        }

        if (kind != "blocked")
        {
            logs.Add(allowedLog);
        }

        var page = TrafficQuery.Run(TrafficHistory.Read(logs, from), new TrafficFilter(kind, from, Sort: "count", Limit: Math.Clamp(request.Limit, 1, TrafficFilter.MaxLimit)));
        return new ActivityUpload(request.RequestId, nowUtc, page);
    }
}

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase, WriteIndented = false, DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
[JsonSerializable(typeof(EnrollRequest))]
[JsonSerializable(typeof(EnrollResponse))]
[JsonSerializable(typeof(CheckinReport))]
[JsonSerializable(typeof(CheckinResponse))]
[JsonSerializable(typeof(ActivityUpload))]
[JsonSerializable(typeof(ManagedPolicy))]
[JsonSerializable(typeof(ServerLink))]
public sealed partial class ManagementJson : JsonSerializerContext
{
}
