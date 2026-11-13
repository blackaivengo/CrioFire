using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace CrioFire.Server;

/// <summary>An administrator of the console. Only a salted PBKDF2 hash of the password is kept.</summary>
public sealed record AdminAccount(string Name, string Hash, string Salt, int Iterations, DateTime CreatedUtc)
{
    public DateTime? LastSignInUtc { get; init; }
}

/// <summary>The console's administrators: %ProgramData%\criofire-server\admins.json. Thread-safe.</summary>
public sealed class AdminAccounts(string folder)
{
    public const int MinPasswordLength = 10;
    private const int Iterations = 210_000;

    private readonly Lock _gate = new();

    private string FilePath { get; } = Path.Combine(folder, "admins.json");

    public IReadOnlyList<AdminAccount> List()
    {
        lock (_gate)
        {
            return Load().OrderBy(a => a.Name, StringComparer.OrdinalIgnoreCase).ToList();
        }
    }

    public bool Any() => List().Count > 0;

    public void Add(string name, string password, DateTime nowUtc)
    {
        name = CheckName(name);
        CheckPassword(password);
        lock (_gate)
        {
            var admins = Load();
            if (admins.Any(a => Same(a.Name, name)))
            {
                throw new ArgumentException($"There is already an administrator called {name}.");
            }

            admins.Add(Create(name, password, nowUtc));
            Save(admins);
        }
    }

    /// <summary>Adds the first administrator; false (and nothing changes) when there already is one.</summary>
    public bool AddFirst(string name, string password, DateTime nowUtc)
    {
        lock (_gate)
        {
            if (Load().Count > 0)
            {
                return false;
            }

            Add(name, password, nowUtc);
            return true;
        }
    }

    public void SetPassword(string name, string password)
    {
        CheckPassword(password);
        lock (_gate)
        {
            var admins = Load();
            var i = admins.FindIndex(a => Same(a.Name, name));
            if (i < 0)
            {
                throw new ArgumentException($"No administrator called {name}.");
            }

            var fresh = Create(admins[i].Name, password, admins[i].CreatedUtc);
            admins[i] = fresh with { LastSignInUtc = admins[i].LastSignInUtc };
            Save(admins);
        }
    }

    /// <summary>Removes an administrator; the last one cannot be removed (nobody could sign in).</summary>
    public void Remove(string name)
    {
        lock (_gate)
        {
            var admins = Load();
            if (admins.Count == 1 && Same(admins[0].Name, name))
            {
                throw new ArgumentException("The last administrator cannot be removed.");
            }

            if (admins.RemoveAll(a => Same(a.Name, name)) == 0)
            {
                throw new ArgumentException($"No administrator called {name}.");
            }

            Save(admins);
        }
    }

    /// <summary>The account when the password is right, otherwise null. Takes the same time for unknown names.</summary>
    public AdminAccount? Verify(string? name, string? password, DateTime nowUtc)
    {
        lock (_gate)
        {
            var admins = Load();
            var i = admins.FindIndex(a => Same(a.Name, name ?? string.Empty));
            var account = i >= 0 ? admins[i] : null;
            var salt = account is null ? new byte[16] : Convert.FromBase64String(account.Salt);
            var hash = Derive(password ?? string.Empty, salt, account?.Iterations ?? Iterations);
            if (account is null || !CryptographicOperations.FixedTimeEquals(hash, Convert.FromBase64String(account.Hash)))
            {
                return null;
            }

            admins[i] = account with { LastSignInUtc = nowUtc };
            Save(admins);
            return admins[i];
        }
    }

    private static AdminAccount Create(string name, string password, DateTime createdUtc)
    {
        var salt = RandomNumberGenerator.GetBytes(16);
        return new AdminAccount(name, Convert.ToBase64String(Derive(password, salt, Iterations)), Convert.ToBase64String(salt), Iterations, createdUtc);
    }

    private static byte[] Derive(string password, byte[] salt, int iterations) =>
        Rfc2898DeriveBytes.Pbkdf2(Encoding.UTF8.GetBytes(password), salt, iterations, HashAlgorithmName.SHA256, 32);

    private static bool Same(string a, string b) => string.Equals(a, b, StringComparison.OrdinalIgnoreCase);

    private static string CheckName(string name)
    {
        var trimmed = name?.Trim() ?? string.Empty;
        return trimmed.Length is > 0 and <= 40 && trimmed.All(c => char.IsLetterOrDigit(c) || c is '.' or '-' or '_' or '@')
            ? trimmed
            : throw new ArgumentException("Names are 1 to 40 letters, digits, '.', '-', '_' or '@'.");
    }

    private static void CheckPassword(string password)
    {
        if (string.IsNullOrEmpty(password) || password.Length < MinPasswordLength)
        {
            throw new ArgumentException($"Use a password of at least {MinPasswordLength} characters.");
        }
    }

    private List<AdminAccount> Load()
    {
        try
        {
            return File.Exists(FilePath) ? JsonSerializer.Deserialize(File.ReadAllText(FilePath), AdminJson.Default.ListAdminAccount) ?? [] : [];
        }
        catch (JsonException)
        {
            return [];
        }
    }

    private void Save(List<AdminAccount> admins)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(FilePath)!);
        File.WriteAllText(FilePath + ".tmp", JsonSerializer.Serialize(admins, AdminJson.Default.ListAdminAccount));
        File.Move(FilePath + ".tmp", FilePath, overwrite: true);
    }
}

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase, WriteIndented = true, DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
[JsonSerializable(typeof(List<AdminAccount>))]
internal sealed partial class AdminJson : JsonSerializerContext
{
}
