using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using CrioFire.Core;
using CrioFire.Core.Management;

namespace CrioFire.Server;

/// <summary>A one-time or multi-use code the admin gives out so PCs can enroll. Only its hash is kept.</summary>
public sealed record EnrollmentToken(string Id, string Hash, DateTime CreatedUtc, DateTime ExpiresUtc, int UsesLeft, string? Note);

/// <summary>
/// A policy: the organization's rules for the PCs it is assigned to, and what their users may
/// still change. Every edit raises the version; PCs pick it up at their next check-in.
/// </summary>
public sealed record ServerPolicy(string Id, string Name, int Version, string? Mode, bool AllowUserRules, bool RequireAdmin, RuleSet Rules, DateTime UpdatedUtc)
{
    public ManagedPolicy ToManaged() => new(Id, Version, Name, Mode, AllowUserRules, RequireAdmin, Rules, UpdatedUtc);
}

/// <summary>An enrolled PC. The secret it authenticates with is kept only as a hash.</summary>
public sealed record DeviceRecord(string DeviceId, string SecretHash, string Computer, DateTime EnrolledUtc)
{
    public DateTime? LastSeenUtc { get; init; }

    public string? Address { get; init; }

    public CheckinReport? LastReport { get; init; }

    public DateTime? ActivityUploadedUtc { get; init; }
}

/// <summary>
/// The server's data, in %ProgramData%\criofire-server: devices.json (enrolled PCs and what they
/// last reported; written by the server) and one file per enrollment token in tokens\ (written by
/// whoever creates a token, so the command line can add tokens while the server runs).
/// Thread-safe.
/// </summary>
public sealed class ServerStore
{
    public const string TokenPrefix = "cfe_";

    private readonly Lock _gate = new();
    private readonly List<DeviceRecord> _devices;
    private bool _dirty;

    public ServerStore(string folder)
    {
        Folder = folder;
        Directory.CreateDirectory(TokenFolder);
        _devices = LoadDevices();
    }

    public static string DefaultFolder => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "criofire-server");

    public string Folder { get; }

    private string TokenFolder => Path.Combine(Folder, "tokens");

    private string DevicesPath => Path.Combine(Folder, "devices.json");

    private string ActivityFolder => Path.Combine(Folder, "activity");

    /// <summary>Requests for connections, one file per PC, so the command line can ask while the server runs.</summary>
    private string RequestFolder => Path.Combine(Folder, "requests");

    /// <summary>One file per policy, and default.txt naming the policy new PCs get.</summary>
    private string PolicyFolder => Path.Combine(Folder, "policies");

    /// <summary>One file per PC naming its policy.</summary>
    private string AssignmentFolder => Path.Combine(Folder, "assignments");

    public ServerPolicy CreatePolicy(string name, RuleSet rules, string? mode, bool allowUserRules, bool requireAdmin, DateTime nowUtc)
    {
        var policy = new ServerPolicy(
            "pol_" + Convert.ToHexString(RandomNumberGenerator.GetBytes(4)).ToLowerInvariant(),
            CheckName(name),
            1,
            CheckMode(mode),
            allowUserRules,
            requireAdmin,
            CheckRules(rules),
            nowUtc);
        WritePolicy(policy);
        return policy;
    }

    /// <summary>Changes a policy; its version goes up, so every PC with it applies the change at its next check-in.</summary>
    public ServerPolicy UpdatePolicy(string id, Func<ServerPolicy, ServerPolicy> change, DateTime nowUtc)
    {
        ArgumentNullException.ThrowIfNull(change);
        lock (_gate)
        {
            var old = Policy(id) ?? throw new ArgumentException($"No policy {id}.");
            var changed = change(old);
            var policy = changed with
            {
                Id = old.Id,
                Name = CheckName(changed.Name),
                Mode = CheckMode(changed.Mode),
                Rules = CheckRules(changed.Rules),
                Version = old.Version + 1,
                UpdatedUtc = nowUtc,
            };
            WritePolicy(policy);
            return policy;
        }
    }

    public IReadOnlyList<ServerPolicy> Policies()
    {
        Directory.CreateDirectory(PolicyFolder);
        return Directory.EnumerateFiles(PolicyFolder, "pol_*.json")
            .Select(p => Policy(Path.GetFileNameWithoutExtension(p)))
            .OfType<ServerPolicy>()
            .OrderBy(p => p.Name, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    public ServerPolicy? Policy(string id)
    {
        var path = Path.Combine(PolicyFolder, id + ".json");
        if (!IsId(id) || !id.StartsWith("pol_", StringComparison.Ordinal) || !File.Exists(path))
        {
            return null;
        }

        try
        {
            return JsonSerializer.Deserialize(File.ReadAllText(path), ServerJson.Default.ServerPolicy);
        }
        catch (Exception ex) when (ex is JsonException or IOException)
        {
            return null;
        }
    }

    /// <summary>Deletes a policy. PCs that had it remove its rules at their next check-in.</summary>
    public bool DeletePolicy(string id)
    {
        lock (_gate)
        {
            if (Policy(id) is null)
            {
                return false;
            }

            File.Delete(Path.Combine(PolicyFolder, id + ".json"));
            if (DefaultPolicyId() == id)
            {
                SetDefaultPolicy(null);
            }

            return true;
        }
    }

    /// <summary>Gives a PC a policy, or none (null).</summary>
    public void Assign(string deviceId, string? policyId)
    {
        if (!IsId(deviceId))
        {
            throw new ArgumentException("No such PC.");
        }

        if (policyId is not null && Policy(policyId) is null)
        {
            throw new ArgumentException($"No policy {policyId}.");
        }

        Directory.CreateDirectory(AssignmentFolder);
        var path = Path.Combine(AssignmentFolder, deviceId + ".txt");
        if (policyId is null)
        {
            DeleteIfExists(path);
        }
        else
        {
            File.WriteAllText(path, policyId);
        }
    }

    /// <summary>The policy a PC has, or null.</summary>
    public ServerPolicy? AssignedPolicy(string deviceId)
    {
        var path = Path.Combine(AssignmentFolder, deviceId + ".txt");
        return IsId(deviceId) && File.Exists(path) ? Policy(File.ReadAllText(path).Trim()) : null;
    }

    /// <summary>The policy PCs get when they enroll, or null.</summary>
    public string? DefaultPolicyId()
    {
        var path = Path.Combine(PolicyFolder, "default.txt");
        return File.Exists(path) && File.ReadAllText(path).Trim() is { Length: > 0 } id && Policy(id) is not null ? id : null;
    }

    public void SetDefaultPolicy(string? policyId)
    {
        if (policyId is not null && Policy(policyId) is null)
        {
            throw new ArgumentException($"No policy {policyId}.");
        }

        Directory.CreateDirectory(PolicyFolder);
        var path = Path.Combine(PolicyFolder, "default.txt");
        if (policyId is null)
        {
            DeleteIfExists(path);
        }
        else
        {
            File.WriteAllText(path, policyId);
        }
    }

    private void WritePolicy(ServerPolicy policy)
    {
        Directory.CreateDirectory(PolicyFolder);
        var path = Path.Combine(PolicyFolder, policy.Id + ".json");
        File.WriteAllText(path + ".tmp", JsonSerializer.Serialize(policy, ServerJson.Default.ServerPolicy));
        File.Move(path + ".tmp", path, overwrite: true);
    }

    private static string CheckName(string name) =>
        string.IsNullOrWhiteSpace(name) || name.Trim().Length > 80 ? throw new ArgumentException("A policy needs a name of up to 80 characters.") : name.Trim();

    private static string? CheckMode(string? mode) =>
        mode is null || FilterDescriptions.TryParseMode(mode, out _) ? mode?.ToLowerInvariant() : throw new ArgumentException("mode must be learning, ask or allowlist.");

    private static RuleSet CheckRules(RuleSet rules) =>
        RuleBackup.Validate(rules ?? throw new ArgumentException("A policy needs rules (they may be empty).")) is { } error ? throw new ArgumentException(error) : rules;

    /// <summary>Creates an enrollment token. The token text is returned once and never stored.</summary>
    public (string Token, EnrollmentToken Record) CreateToken(TimeSpan validFor, int uses, string? note, DateTime nowUtc)
    {
        if (uses < 1)
        {
            throw new ArgumentException("A token needs at least one use.");
        }

        var token = TokenPrefix + Base64Url(RandomNumberGenerator.GetBytes(24));
        var record = new EnrollmentToken(
            "tok_" + Convert.ToHexString(RandomNumberGenerator.GetBytes(4)).ToLowerInvariant(),
            Hash(token),
            nowUtc,
            nowUtc + validFor,
            uses,
            note);
        SaveToken(record);
        return (token, record);
    }

    public IReadOnlyList<EnrollmentToken> Tokens()
    {
        lock (_gate)
        {
            return Directory.EnumerateFiles(TokenFolder, "tok_*.json")
                .Select(ReadToken)
                .OfType<EnrollmentToken>()
                .OrderByDescending(t => t.CreatedUtc)
                .ToList();
        }
    }

    public bool RevokeToken(string id)
    {
        lock (_gate)
        {
            var path = TokenPath(id);
            if (path is null || !File.Exists(path))
            {
                return false;
            }

            File.Delete(path);
            return true;
        }
    }

    /// <summary>Enrolls a PC with a valid token. Returns null and why when the token is wrong, used up or expired.</summary>
    public EnrollResponse? Enroll(EnrollRequest request, string serverName, string? address, DateTime nowUtc, out string? error)
    {
        ArgumentNullException.ThrowIfNull(request);
        error = null;
        if (string.IsNullOrWhiteSpace(request.Computer) || request.Computer.Length > 64)
        {
            error = "The computer name is missing or too long.";
            return null;
        }

        lock (_gate)
        {
            var hash = Hash(request.Token ?? string.Empty);
            var token = Tokens().FirstOrDefault(t => FixedEquals(t.Hash, hash));
            if (token is null || token.UsesLeft < 1)
            {
                error = "The enrollment token is not valid. Ask your administrator for a new one.";
                return null;
            }

            if (token.ExpiresUtc <= nowUtc)
            {
                error = "The enrollment token has expired. Ask your administrator for a new one.";
                return null;
            }

            if (token.UsesLeft == 1)
            {
                RevokeToken(token.Id);
            }
            else
            {
                SaveToken(token with { UsesLeft = token.UsesLeft - 1 });
            }

            var secret = Base64Url(RandomNumberGenerator.GetBytes(32));
            var device = new DeviceRecord(
                "dev_" + Convert.ToHexString(RandomNumberGenerator.GetBytes(6)).ToLowerInvariant(),
                Hash(secret),
                request.Computer.Trim(),
                nowUtc)
            {
                LastSeenUtc = nowUtc,
                Address = address,
            };

            // A PC enrolling again (reinstalled, or moved to this server again) replaces its old entry.
            _devices.RemoveAll(d => string.Equals(d.Computer, device.Computer, StringComparison.OrdinalIgnoreCase));
            _devices.Add(device);
            SaveDevicesLocked();
            Assign(device.DeviceId, DefaultPolicyId());
            return new EnrollResponse(device.DeviceId, secret, serverName);
        }
    }

    /// <summary>The device an "Authorization: Device id.secret" header belongs to, or null.</summary>
    public DeviceRecord? Authenticate(string? authorization)
    {
        var prefix = ManagementClient.DeviceScheme + " ";
        if (authorization is null || !authorization.StartsWith(prefix, StringComparison.Ordinal))
        {
            return null;
        }

        var credential = authorization[prefix.Length..].Trim();
        var dot = credential.IndexOf('.', StringComparison.Ordinal);
        if (dot <= 0)
        {
            return null;
        }

        var id = credential[..dot];
        var hash = Hash(credential[(dot + 1)..]);
        lock (_gate)
        {
            var device = _devices.FirstOrDefault(d => d.DeviceId == id);
            return device is not null && FixedEquals(device.SecretHash, hash) ? device : null;
        }
    }

    public void RecordCheckin(string deviceId, CheckinReport report, string? address, DateTime nowUtc)
    {
        ArgumentNullException.ThrowIfNull(report);
        lock (_gate)
        {
            var i = _devices.FindIndex(d => d.DeviceId == deviceId);
            if (i < 0)
            {
                return;
            }

            _devices[i] = _devices[i] with { LastSeenUtc = nowUtc, LastReport = report, Address = address, Computer = Clip(report.Computer, _devices[i].Computer) };
            _dirty = true;
        }
    }

    /// <summary>The device with this ID, or with this computer name.</summary>
    public DeviceRecord? Find(string deviceOrComputer)
    {
        lock (_gate)
        {
            return _devices.FirstOrDefault(d => d.DeviceId == deviceOrComputer)
                ?? _devices.FirstOrDefault(d => string.Equals(d.Computer, deviceOrComputer, StringComparison.OrdinalIgnoreCase));
        }
    }

    /// <summary>
    /// Asks one PC for its connections. The PC sends them after its next check-in; nothing is sent
    /// unless an administrator asks, so many PCs never flood the server.
    /// </summary>
    public ActivityRequest RequestActivity(string deviceId, string kind, int hours, int limit, DateTime nowUtc)
    {
        if (kind is not ("blocked" or "allowed" or "all"))
        {
            throw new ArgumentException("kind must be blocked, allowed or all.");
        }

        var request = new ActivityRequest(
            "act_" + Convert.ToHexString(RandomNumberGenerator.GetBytes(4)).ToLowerInvariant(),
            kind,
            Math.Clamp(hours, 1, 720),
            Math.Clamp(limit, 1, 500),
            nowUtc);
        if (!IsId(deviceId))
        {
            throw new ArgumentException("No such PC.");
        }

        lock (_gate)
        {
            Directory.CreateDirectory(RequestFolder);
            var path = Path.Combine(RequestFolder, deviceId + ".json");
            File.WriteAllText(path + ".tmp", JsonSerializer.Serialize(request, ServerJson.Default.ActivityRequest));
            File.Move(path + ".tmp", path, overwrite: true);
        }

        return request;
    }

    /// <summary>The open request for a PC's connections, if an administrator made one.</summary>
    public ActivityRequest? PendingActivity(string deviceId)
    {
        var path = Path.Combine(RequestFolder, deviceId + ".json");
        if (!IsId(deviceId) || !File.Exists(path))
        {
            return null;
        }

        try
        {
            return JsonSerializer.Deserialize(File.ReadAllText(path), ServerJson.Default.ActivityRequest);
        }
        catch (Exception ex) when (ex is JsonException or IOException)
        {
            return null;
        }
    }

    /// <summary>Keeps a PC's answer to an activity request. Uploads nobody asked for are refused.</summary>
    public bool StoreActivity(string deviceId, ActivityUpload upload, DateTime nowUtc)
    {
        ArgumentNullException.ThrowIfNull(upload);
        lock (_gate)
        {
            var i = _devices.FindIndex(d => d.DeviceId == deviceId);
            if (i < 0 || PendingActivity(deviceId)?.RequestId != upload.RequestId)
            {
                return false;
            }

            Directory.CreateDirectory(ActivityFolder);
            var path = Path.Combine(ActivityFolder, deviceId + ".json");
            File.WriteAllText(path + ".tmp", JsonSerializer.Serialize(upload, ManagementJson.Default.ActivityUpload));
            File.Move(path + ".tmp", path, overwrite: true);
            File.Delete(Path.Combine(RequestFolder, deviceId + ".json"));
            _devices[i] = _devices[i] with { ActivityUploadedUtc = nowUtc };
            SaveDevicesLocked();
            return true;
        }
    }

    /// <summary>The connections a PC sent last, or null.</summary>
    public ActivityUpload? Activity(string deviceId)
    {
        var path = Path.Combine(ActivityFolder, deviceId + ".json");
        if (!IsId(deviceId) || !File.Exists(path))
        {
            return null;
        }

        try
        {
            return JsonSerializer.Deserialize(File.ReadAllText(path), ManagementJson.Default.ActivityUpload);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    public IReadOnlyList<DeviceRecord> Devices()
    {
        lock (_gate)
        {
            return _devices.OrderBy(d => d.Computer, StringComparer.OrdinalIgnoreCase).ToList();
        }
    }

    public bool RemoveDevice(string deviceId)
    {
        lock (_gate)
        {
            var removed = _devices.RemoveAll(d => d.DeviceId == deviceId) > 0;
            if (removed)
            {
                SaveDevicesLocked();
                DeleteIfExists(Path.Combine(ActivityFolder, deviceId + ".json"));
                DeleteIfExists(Path.Combine(RequestFolder, deviceId + ".json"));
                DeleteIfExists(Path.Combine(AssignmentFolder, deviceId + ".txt"));
            }

            return removed;
        }
    }

    /// <summary>Writes check-ins to disk; called every few seconds, so a check-in costs no disk write.</summary>
    public void SaveIfChanged()
    {
        lock (_gate)
        {
            if (_dirty)
            {
                SaveDevicesLocked();
            }
        }
    }

    private static void DeleteIfExists(string path)
    {
        if (File.Exists(path))
        {
            File.Delete(path);
        }
    }

    private static bool IsId(string id) => id.Length is > 0 and < 40 && id.All(c => char.IsAsciiLetterOrDigit(c) || c == '_');

    public static string Hash(string text) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(text)));

    private static string Clip(string? text, string fallback) =>
        string.IsNullOrWhiteSpace(text) ? fallback : text.Trim().Length > 64 ? text.Trim()[..64] : text.Trim();

    private static bool FixedEquals(string a, string b) =>
        CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(a), Encoding.ASCII.GetBytes(b));

    private static string Base64Url(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private string? TokenPath(string id) =>
        id.StartsWith("tok_", StringComparison.Ordinal) && id.Length < 32 && id.All(c => char.IsAsciiLetterOrDigit(c) || c == '_')
            ? Path.Combine(TokenFolder, id + ".json")
            : null;

    private void SaveToken(EnrollmentToken token)
    {
        var path = TokenPath(token.Id)!;
        var temp = path + ".tmp";
        File.WriteAllText(temp, JsonSerializer.Serialize(token, ServerJson.Default.EnrollmentToken));
        File.Move(temp, path, overwrite: true);
    }

    private static EnrollmentToken? ReadToken(string path)
    {
        try
        {
            return JsonSerializer.Deserialize(File.ReadAllText(path), ServerJson.Default.EnrollmentToken);
        }
        catch (Exception ex) when (ex is JsonException or IOException)
        {
            return null;
        }
    }

    private List<DeviceRecord> LoadDevices()
    {
        try
        {
            return File.Exists(DevicesPath)
                ? JsonSerializer.Deserialize(File.ReadAllText(DevicesPath), ServerJson.Default.ListDeviceRecord) ?? []
                : [];
        }
        catch (JsonException)
        {
            // Keep the damaged file for inspection and start over; PCs can enroll again.
            File.Move(DevicesPath, DevicesPath + ".damaged", overwrite: true);
            return [];
        }
    }

    private void SaveDevicesLocked()
    {
        var temp = DevicesPath + ".tmp";
        File.WriteAllText(temp, JsonSerializer.Serialize(_devices, ServerJson.Default.ListDeviceRecord));
        File.Move(temp, DevicesPath, overwrite: true);
        _dirty = false;
    }
}

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase, WriteIndented = true, DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
[JsonSerializable(typeof(EnrollmentToken))]
[JsonSerializable(typeof(ActivityRequest))]
[JsonSerializable(typeof(ServerPolicy))]
[JsonSerializable(typeof(List<DeviceRecord>))]
internal sealed partial class ServerJson : JsonSerializerContext
{
}
