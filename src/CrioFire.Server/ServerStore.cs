using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using CrioFire.Core.Management;

namespace CrioFire.Server;

/// <summary>A one-time or multi-use code the admin gives out so PCs can enroll. Only its hash is kept.</summary>
public sealed record EnrollmentToken(string Id, string Hash, DateTime CreatedUtc, DateTime ExpiresUtc, int UsesLeft, string? Note);

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
[JsonSerializable(typeof(List<DeviceRecord>))]
internal sealed partial class ServerJson : JsonSerializerContext
{
}
