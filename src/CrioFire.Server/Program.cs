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
//   criofire-server policy ...                                  organization rules for PCs
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
        case "admin" when args.Length >= 2:
            return Commands.Admin(folder, args[1..]);
        case "policy" when args.Length >= 2:
            return Commands.Policy(folder, args[1..]);
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

          criofire-server                         Run the server (normally as the Windows service criofire-server).
                                                  The admin console is at https://<this server>:7443/
          criofire-server admin add <name>        Add an administrator for the console (asks for a password)
          criofire-server admin list | remove <name> | password <name>
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

        Policies (the organization's rules; they win over each PC's own rules):
          criofire-server policy list
          criofire-server policy create <name> --rules <file.json> [--mode learning|ask|allowlist] [--lock] [--protect]
              The rules file is made with 'criofire export' on a PC set up as wanted. --mode sets the mode on
              every PC (otherwise users choose); --lock removes users' own rules and lets them add none;
              --protect switches tamper protection on and keeps it on.
          criofire-server policy update <id> [--rules <file.json>] [--name <name>] [--mode <mode>|--mode any]
                                             [--lock|--unlock] [--protect|--no-protect]
          criofire-server policy assign <id|none> <pc>... | --all
          criofire-server policy default <id|none>    The policy new PCs get when they enroll
          criofire-server policy delete <id>
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

    public static int Admin(string folder, string[] args)
    {
        var admins = new AdminAccounts(folder);
        switch (args[0].ToLowerInvariant())
        {
            case "add" when args.Length == 2:
            case "password" when args.Length == 2:
            {
                var password = Password("Password: ");
                if (password != Password("Same password again: "))
                {
                    throw new ArgumentException("The passwords differ.");
                }

                if (args[0].Equals("add", StringComparison.OrdinalIgnoreCase))
                {
                    admins.Add(args[1], password, DateTime.UtcNow);
                    var settings = ServerSettings.Load(folder);
                    Console.WriteLine($"Added {args[1]}. Sign in at https://{ServerCertificate.HostNames()[^2]}:{settings.Port}/");
                }
                else
                {
                    admins.SetPassword(args[1], password);
                    Console.WriteLine($"Changed the password of {args[1]}.");
                }

                return 0;
            }

            case "list":
                foreach (var a in admins.List())
                {
                    Console.WriteLine($"{a.Name,-24} added {a.CreatedUtc.ToLocalTime():d}, last sign-in {(a.LastSignInUtc is { } t ? t.ToLocalTime().ToString("g", CultureInfo.CurrentCulture) : "never")}");
                }

                return 0;
            case "remove" when args.Length == 2:
                admins.Remove(args[1]);
                Console.WriteLine($"Removed {args[1]}.");
                return 0;
            default:
                Console.WriteLine(Usage);
                return 2;
        }
    }

    private static string Password(string prompt)
    {
        Console.Write(prompt);
        if (Console.IsInputRedirected)
        {
            var line = Console.ReadLine() ?? string.Empty;
            Console.WriteLine();
            return line;
        }

        var chars = new List<char>();
        for (var key = Console.ReadKey(intercept: true); key.Key != ConsoleKey.Enter; key = Console.ReadKey(intercept: true))
        {
            if (key.Key == ConsoleKey.Backspace)
            {
                if (chars.Count > 0)
                {
                    chars.RemoveAt(chars.Count - 1);
                }
            }
            else
            {
                chars.Add(key.KeyChar);
            }
        }

        Console.WriteLine();
        return new string(chars.ToArray());
    }

    public static int Policy(string folder, string[] args)
    {
        var store = new ServerStore(folder);
        var now = DateTime.UtcNow;
        switch (args[0].ToLowerInvariant())
        {
            case "list":
            {
                var policies = store.Policies();
                var byPolicy = store.Devices().GroupBy(d => store.AssignedPolicy(d.DeviceId)?.Id ?? "").ToDictionary(g => g.Key, g => g.Count());
                if (policies.Count == 0)
                {
                    Console.WriteLine("No policies yet. Create one from a PC's exported rules: criofire-server policy create <name> --rules <file.json>");
                }

                var fallback = store.DefaultPolicyId();
                foreach (var p in policies)
                {
                    Console.WriteLine($"{p.Id,-14} {p.Name}{(p.Id == fallback ? "  (default for new PCs)" : string.Empty)}");
                    Console.WriteLine($"               version {p.Version}, {p.Rules.Count} rules, mode {p.Mode ?? "users choose"}, "
                        + $"{(p.AllowUserRules ? "users may add rules" : "locked")}{(p.RequireAdmin ? ", tamper protection" : string.Empty)}, "
                        + $"{byPolicy.GetValueOrDefault(p.Id)} PC(s)");
                }

                return 0;
            }

            case "create" when args.Length >= 2:
            {
                var options = PolicyOptions.Parse(args[2..]);
                var rules = options.Rules ?? throw new ArgumentException("Give the rules: --rules <file.json> (from 'criofire export').");
                var policy = store.CreatePolicy(args[1], rules, options.Mode, !(options.Lock ?? false), options.Protect ?? false, now);
                Console.WriteLine($"Created {policy.Id} \"{policy.Name}\" with {policy.Rules.Count} rules. Give it to PCs with: criofire-server policy assign {policy.Id} <pc>... | --all");
                return 0;
            }

            case "update" when args.Length >= 2:
            {
                var options = PolicyOptions.Parse(args[2..]);
                var policy = store.UpdatePolicy(args[1], p => p with
                {
                    Name = options.Name ?? p.Name,
                    Rules = options.Rules ?? p.Rules,
                    Mode = options.ModeGiven ? options.Mode : p.Mode,
                    AllowUserRules = options.Lock is { } locked ? !locked : p.AllowUserRules,
                    RequireAdmin = options.Protect ?? p.RequireAdmin,
                }, now);
                Console.WriteLine($"Updated {policy.Id} to version {policy.Version}. PCs with it apply the change at their next check-in.");
                return 0;
            }

            case "assign" when args.Length >= 3:
            {
                var policyId = args[1].Equals("none", StringComparison.OrdinalIgnoreCase) ? null : args[1];
                var devices = args[2] == "--all"
                    ? store.Devices()
                    : args[2..].Select(pc => store.Find(pc) ?? throw new ArgumentException($"No enrolled PC called {pc}.")).ToList();
                foreach (var d in devices)
                {
                    store.Assign(d.DeviceId, policyId);
                }

                Console.WriteLine(policyId is null
                    ? $"{devices.Count} PC(s) have no policy now; they remove the organization's rules at their next check-in."
                    : $"{devices.Count} PC(s) get {policyId} at their next check-in.");
                return 0;
            }

            case "default" when args.Length == 2:
            {
                var policyId = args[1].Equals("none", StringComparison.OrdinalIgnoreCase) ? null : args[1];
                store.SetDefaultPolicy(policyId);
                Console.WriteLine(policyId is null ? "New PCs get no policy." : $"New PCs get {policyId} when they enroll.");
                return 0;
            }

            case "delete" when args.Length == 2:
            {
                var ok = store.DeletePolicy(args[1]);
                Console.WriteLine(ok ? $"Deleted {args[1]}. PCs that had it remove its rules at their next check-in." : $"No policy {args[1]}.");
                return ok ? 0 : 1;
            }

            default:
                Console.WriteLine(Usage);
                return 2;
        }
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

/// <summary>The options of policy create and update.</summary>
internal sealed record PolicyOptions(string? Name, CrioFire.Core.RuleSet? Rules, string? Mode, bool ModeGiven, bool? Lock, bool? Protect)
{
    public static PolicyOptions Parse(string[] args)
    {
        string? name = null, mode = null;
        CrioFire.Core.RuleSet? rules = null;
        bool modeGiven = false;
        bool? locked = null, protect = null;
        for (var i = 0; i < args.Length; i++)
        {
            string Value() => i + 1 < args.Length ? args[++i] : throw new ArgumentException($"{args[i]} needs a value.");
            switch (args[i])
            {
                case "--name": name = Value(); break;
                case "--rules": rules = CrioFire.Core.RuleBackup.FromJson(File.ReadAllText(Value())); break;
                case "--mode":
                    var m = Value().ToLowerInvariant();
                    mode = m == "any" ? null : m;
                    modeGiven = true;
                    break;
                case "--lock": locked = true; break;
                case "--unlock": locked = false; break;
                case "--protect": protect = true; break;
                case "--no-protect": protect = false; break;
                default: throw new ArgumentException($"Unknown option {args[i]}.");
            }
        }

        return new PolicyOptions(name, rules, mode, modeGiven, locked, protect);
    }
}
