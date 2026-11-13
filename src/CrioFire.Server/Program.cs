using System.Globalization;
using System.Text.Json;
using CrioFire.Core.Management;
using CrioFire.Server;

// CrioFire Server. Without arguments (as the Windows service "criofire-server") it serves PCs on
// https://<this machine>:7443. The other commands manage enrollment from an administrator prompt:
//   criofire-server token [--days N] [--uses N] [--note text]   a code PCs enroll with
//   criofire-server tokens | revoke <id>                        list or cancel codes
//   criofire-server devices                                     the enrolled PCs
//   criofire-server activity <pc> [--hours N] [--kind K] | --show  ask one PC for its connections
//   criofire-server fingerprint                                 the certificate PCs pin

// CRIOFIRE_SERVER_DATA moves the data folder (tests, or a different disk).
var folder = Environment.GetEnvironmentVariable("CRIOFIRE_SERVER_DATA") is { Length: > 0 } custom ? custom : ServerStore.DefaultFolder;
var settings = ServerSettings.Load(folder);
var command = args.Length == 0 ? "run" : args[0].ToLowerInvariant();
try
{
    switch (command)
    {
        case "run":
            await ServerHost.RunAsync(args, folder, settings).ConfigureAwait(false);
            return 0;
        case "token":
            return Commands.Token(folder, settings, args[1..]);
        case "tokens":
            return Commands.Tokens(folder);
        case "revoke" when args.Length == 2:
            return Commands.Revoke(folder, args[1]);
        case "devices":
            return Commands.Devices(folder);
        case "activity" when args.Length >= 2:
            return Commands.Activity(folder, args[1], args[2..]);
        case "fingerprint":
            Console.WriteLine(Fingerprints.Of(ServerCertificate.LoadOrCreate(folder, DateTime.UtcNow)));
            return 0;
        default:
            Console.WriteLine(Commands.Usage);
            return 2;
    }
}
catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or FormatException)
{
    Console.Error.WriteLine(ex.Message);
    return 1;
}

/// <summary>%ProgramData%\criofire-server\settings.json: the port (default 7443) and how often PCs check in (default 300 s).</summary>
internal sealed record ServerSettings(int Port = ServerDefaults.Port, int CheckinSeconds = ServerDefaults.CheckinSeconds)
{
    public static ServerSettings Load(string folder)
    {
        var path = Path.Combine(folder, "settings.json");
        if (!File.Exists(path))
        {
            return new ServerSettings();
        }

        using var doc = JsonDocument.Parse(File.ReadAllText(path));
        var settings = new ServerSettings();
        if (doc.RootElement.TryGetProperty("port", out var port) && port.TryGetInt32(out var p) && p is > 0 and < 65536)
        {
            settings = settings with { Port = p };
        }

        if (doc.RootElement.TryGetProperty("checkinSeconds", out var every) && every.TryGetInt32(out var s))
        {
            settings = settings with { CheckinSeconds = Math.Clamp(s, ServerDefaults.MinCheckinSeconds, ServerDefaults.MaxCheckinSeconds) };
        }

        return settings;
    }
}

internal static class Commands
{
    public const string Usage = """
        CrioFire Server

          criofire-server                         Run the server (normally as the Windows service criofire-server)
          criofire-server token [--days N] [--uses N] [--note <text>]
                                                  Create an enrollment code (default: 7 days, 1 use) and show
                                                  the command to run on each PC
          criofire-server tokens                  List the enrollment codes that still work
          criofire-server revoke <id>             Cancel an enrollment code
          criofire-server devices                 List the enrolled PCs and when they last checked in
          criofire-server activity <pc> [--hours N] [--kind blocked|allowed|all] [--limit N]
                                                  Ask one PC for what it blocked and allowed (default: blocked,
                                                  24 hours, 200 rows); it answers after its next check-in
          criofire-server activity <pc> --show    Show what that PC sent
          criofire-server fingerprint             Show the server certificate's fingerprint
        """;

    public static int Token(string folder, ServerSettings settings, string[] args)
    {
        var days = 7;
        var uses = 1;
        string? note = null;
        for (var i = 0; i + 1 < args.Length; i += 2)
        {
            switch (args[i])
            {
                case "--days": days = int.Parse(args[i + 1], CultureInfo.InvariantCulture); break;
                case "--uses": uses = int.Parse(args[i + 1], CultureInfo.InvariantCulture); break;
                case "--note": note = args[i + 1]; break;
                default: throw new ArgumentException($"Unknown option {args[i]}.");
            }
        }

        if (args.Length % 2 != 0 || days is < 1 or > 365 || uses is < 1 or > 100_000)
        {
            Console.WriteLine(Usage);
            return 2;
        }

        var store = new ServerStore(folder);
        var (token, record) = store.CreateToken(TimeSpan.FromDays(days), uses, note, DateTime.UtcNow);
        var fingerprint = Fingerprints.Of(ServerCertificate.LoadOrCreate(folder, DateTime.UtcNow));
        var host = ServerCertificate.HostNames()[^2];
        Console.WriteLine($"Enrollment code {record.Id}: {uses} use(s), until {record.ExpiresUtc.ToLocalTime():g}.");
        Console.WriteLine();
        Console.WriteLine("On each PC, from an administrator prompt:");
        Console.WriteLine($"  criofire enroll {host}:{settings.Port} {token} --fingerprint {fingerprint}");
        return 0;
    }

    public static int Tokens(string folder)
    {
        var tokens = new ServerStore(folder).Tokens().Where(t => t.ExpiresUtc > DateTime.UtcNow).ToList();
        if (tokens.Count == 0)
        {
            Console.WriteLine("No enrollment codes. Create one with: criofire-server token");
        }

        foreach (var t in tokens)
        {
            Console.WriteLine($"{t.Id,-14} {t.UsesLeft,6} use(s) left, until {t.ExpiresUtc.ToLocalTime():g}  {t.Note}");
        }

        return 0;
    }

    public static int Revoke(string folder, string id)
    {
        var ok = new ServerStore(folder).RevokeToken(id);
        Console.WriteLine(ok ? $"Cancelled {id}." : $"No enrollment code {id}.");
        return ok ? 0 : 1;
    }

    public static int Devices(string folder)
    {
        var store = new ServerStore(folder);
        var devices = store.Devices();
        if (devices.Count == 0)
        {
            Console.WriteLine("No PCs enrolled yet.");
        }

        foreach (var d in devices)
        {
            var r = d.LastReport;
            var seen = d.LastSeenUtc is { } s ? s.ToLocalTime().ToString("g", CultureInfo.CurrentCulture) : "never";
            var state = r is null ? string.Empty : $"{r.Mode}{(r.Panic != "off" ? ", PANIC " + r.Panic : string.Empty)}, {r.ProgramRules + r.NetworkRules + r.ServiceRules} rules"
                + (r.ChangedPrograms > 0 ? $", {r.ChangedPrograms} changed program(s)" : string.Empty)
                + (store.PendingActivity(d.DeviceId) is not null ? ", activity requested" : string.Empty);
            Console.WriteLine($"{d.Computer,-20} {d.DeviceId,-18} last check-in {seen,-20} {state}");
        }

        return 0;
    }

    public static int Activity(string folder, string pc, string[] args)
    {
        var store = new ServerStore(folder);
        var device = store.Find(pc) ?? throw new ArgumentException($"No enrolled PC called {pc}. See: criofire-server devices");
        if (args is ["--show"])
        {
            if (store.Activity(device.DeviceId) is not { } upload)
            {
                Console.WriteLine(store.PendingActivity(device.DeviceId) is not null
                    ? $"{device.Computer} has not answered yet; it will after its next check-in."
                    : $"Nothing from {device.Computer} yet. Ask with: criofire-server activity {device.Computer}");
                return 0;
            }

            Console.WriteLine($"{device.Computer}, sent {upload.CreatedUtc.ToLocalTime():g}: {upload.Page.Total} rows, {upload.Page.Connections} connections");
            foreach (var row in upload.Page.Items)
            {
                Console.WriteLine($"{(row.Allowed ? "allowed" : "blocked"),-8} {row.Count,6}x  {row.App ?? "?"}  -> {row.Remote}:{row.Port} {row.Protocol}  ({row.WhyLabel})");
            }

            return 0;
        }

        string kind = "blocked";
        int hours = 24, limit = 200;
        for (var i = 0; i + 1 < args.Length; i += 2)
        {
            switch (args[i])
            {
                case "--hours": hours = int.Parse(args[i + 1], CultureInfo.InvariantCulture); break;
                case "--kind": kind = args[i + 1].ToLowerInvariant(); break;
                case "--limit": limit = int.Parse(args[i + 1], CultureInfo.InvariantCulture); break;
                default: throw new ArgumentException($"Unknown option {args[i]}.");
            }
        }

        var request = store.RequestActivity(device.DeviceId, kind, hours, limit, DateTime.UtcNow);
        Console.WriteLine($"Asked {device.Computer} for {request.Kind} connections of the last {request.Hours} hours ({request.RequestId}).");
        Console.WriteLine($"It answers after its next check-in. Then: criofire-server activity {device.Computer} --show");
        return 0;
    }
}
