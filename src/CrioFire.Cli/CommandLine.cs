using CrioFire.Core;

namespace CrioFire.Cli;

public enum CommandKind
{
    Help,
    Version,
    Status,
    Install,
    Uninstall,
    List,
    Block,
    Unblock,
    Remove,
    Panic,
    Events,
    Allow,
    ModeShow,
    ModeSet,
    Setup,
    Allowed,
    AutoShow,
    AutoSet,
    Changed,
    Trust,
    Export,
    Import,
    Backups,
    Restore,
    Request,
    Protection,
    License,
    Enroll,
    Unenroll,
    Server,
    Domains,
    DataUsed,
}

/// <param name="Minutes">events: how far back to look.</param>
/// <param name="All">events: include drops by other firewalls, not only CrioFire's.</param>
/// <param name="Mode">mode: the mode to switch to.</param>
/// <param name="Yes">mode: keep the new mode without the "is your network still working?" check.</param>
/// <param name="AllowRunning">mode: also allow every program running right now.</param>
/// <param name="ExpiresMinutes">allow/block --for N: the rule is removed again after N minutes.</param>
/// <param name="Net">allow/block with --port, --addr, --tcp or --udp: a network rule (program optional).</param>
/// <param name="RemoveData">uninstall --remove-data: also delete %ProgramData%\criofire (logs, temporary rules).</param>
/// <param name="Service">block/allow/unblock --service: a rule for one Windows service.</param>
/// <param name="AutoRule">auto: svchost or system.</param>
/// <param name="Enabled">auto ... on|off.</param>
/// <param name="FilePath">export/import: the rules file. restore: the backup name.</param>
/// <param name="Replace">import --replace: also remove rules that are not in the file.</param>
/// <param name="DryRun">import/restore --dry-run: only show what would change.</param>
/// <param name="WithMode">import --with-mode: also switch to the mode in the file.</param>
/// <param name="Networks">block/allow --networks: the kinds of network the rule applies on (every network by default).</param>
/// <param name="Domain">block/allow/unblock --domain: a rule for a domain and every name under it.</param>
public sealed record Command(
    CommandKind Kind,
    string? AppPath = null,
    TrafficDirection Direction = TrafficDirection.Outbound,
    ulong FilterId = 0,
    int Minutes = 10,
    bool All = false,
    FirewallMode Mode = FirewallMode.Learning,
    bool Yes = false,
    bool AllowRunning = false,
    int? ExpiresMinutes = null,
    NetRule? Net = null,
    bool RemoveData = false,
    string? Service = null,
    string? AutoRule = null,
    bool Enabled = true,
    string? PanicAction = null,
    string? FilePath = null,
    bool Replace = false,
    bool DryRun = false,
    bool WithMode = false,
    string? Server = null,
    string? Token = null,
    string? Fingerprint = null,
    NetworkProfiles Networks = NetworkProfiles.Any,
    string? Domain = null);

/// <summary>Parses criofire.exe arguments. Pure logic, no Windows calls, so it is unit-tested.</summary>
internal static class CommandLine
{
    public const string Usage = """
        CrioFire Private Firewall - command line (prototype)

        Usage:
          criofire status                      Show whether CrioFire is installed and how many rules exist
          criofire install                     Register CrioFire with the Windows Filtering Platform
          criofire list                        List CrioFire's rules
          criofire block <app.exe> [--out|--in|--both] [--for <minutes>]
                                               Block one program (default: outbound)
          criofire allow <app.exe> [--out|--in|--both] [--for <minutes>]
                                               Allow one program (default: outbound); matters in ask/allowlist mode.
                                               --for makes it temporary (needs the criofire service running)
          criofire unblock <app.exe> [--out|--in|--both]
                                               Remove CrioFire's rules for one program (default: both)
          criofire block|allow [<app.exe>] [--tcp|--udp] [--port <ports>] [--addr <addresses>]
                               [--out|--in|--both]
                                               A network rule: by port (80,443,8000-8100; the remote port
                                               outbound, the local port inbound) and/or remote address
                                               (203.0.113.5, 10.0.0.0/8, 10.0.0.1-10.0.0.50), optionally
                                               only for one program. Examples:
                                                 criofire block --in --tcp --port 445
                                                 criofire allow "C:\Apps\chat.exe" --port 443
                                                 criofire block --addr 203.0.113.0/24
                                               More specific rules win, and block wins a tie. Remove one
                                               with criofire remove <filter-id> (all its filters go).
          criofire block|allow|unblock --service <name> [--out|--in|--both]
                                               A rule for one Windows service, even inside a shared
                                               svchost.exe (matched by its service SID), e.g.
                                                 criofire block --service DiagTrack
          criofire block|allow --domain <name> [<app.exe>] [--networks ...]
                                               A rule for a domain and every name under it (outgoing),
                                               e.g. criofire block --domain doubleclick.net. CrioFire follows
                                               Windows' name lookups and blocks or allows the addresses they
                                               return (sites sharing an address are affected too; a browser's
                                               own encrypted DNS is not seen).
          criofire unblock --domain <name>     Remove your rules for that domain
          criofire domains                     List the domain rules and how many addresses each covers now
          criofire usage [today|7d|30d]        Data each program sent and received (default: today)
          criofire usage --reset               Clear the data counts
          ... block|allow ... --networks <public|private|domain,...>
                                               Any program, network or service rule can apply only on some
                                               kinds of network (as Windows classifies them: domain = work,
                                               private = home, public = everything else); elsewhere the mode
                                               decides. E.g. criofire block --in --tcp --port 445 --networks public
          criofire allowed [--minutes N] [--local]
                                               Show what was allowed to connect and why (default: last
                                               60 minutes; --local also shows loopback traffic)
          criofire auto                        Show CrioFire's automatic rules
          criofire auto <svchost|system|lan> <on|off>
                                               Switch an automatic rule of ask/allowlist mode on or off
                                               (svchost: Windows services such as DNS; off breaks name
                                               lookups for programs without their own rule. lan: every
                                               program may reach the local network, on home and work
                                               networks only; off unless you turn it on)
          criofire mode                        Show the current mode
          criofire mode <learning|ask|allowlist> [--allow-running] [--yes]
                                               learning: programs without a rule may connect
                                               ask / allowlist: they are blocked (outbound; loopback and
                                               Windows services stay allowed)
                                               --allow-running: first allow every program running now
                                               Asks you to confirm the network still works within 60 s,
                                               otherwise switches back (--yes skips the check)
          criofire changed                     Show allowed programs whose file changed since you allowed
                                               them (another publisher, a lost signature, or different
                                               contents of an unsigned program). In ask/allowlist mode
                                               they are blocked until you allow them again
          criofire trust <app.exe>             You checked the changed program: allow it again as it is now
          criofire export <file.json>          Save every rule (program, network, service, automatic rules
                                               and the mode) to a file
          criofire import <file.json> [--replace] [--dry-run] [--with-mode]
                                               Add and update rules from a file. --replace also removes
                                               rules that are not in it; --dry-run only shows what would
                                               change; --with-mode also switches to the file's mode. A
                                               backup is saved first
          criofire backups                     List the saved backups (made automatically when the rules
                                               change, and before every import or "remove all")
          criofire restore <backup> [--dry-run]
                                               Put the rules back exactly as in a backup
          criofire enroll <server> <code> [--fingerprint <sha256>]
                                               Let the company's CrioFire Server manage this PC (the
                                               command to copy is shown when the admin creates a code)
          criofire unenroll                    Stop reporting to the CrioFire Server (rules stay)
          criofire server                      Show the CrioFire Server this PC reports to
          criofire license [<key>|--remove]    Show the license, enter a business license key, or go back
                                               to free use (personal use, non-profits, schools,
                                               government, businesses with up to 3 computers)
          criofire protection [on|off]         Tamper protection: when on, changing rules needs
                                               administrator approval, so a program running as you
                                               cannot use CrioFire to allow itself (changing it needs an
                                               administrator prompt)
          criofire remove <filter-id>          Remove one CrioFire filter by ID
          criofire events [--minutes N] [--all]
                                               Show connections CrioFire blocked (default: last 10 minutes;
                                               --all also shows drops by other firewalls)
          criofire panic [allow|block|off|remove]
                                               allow (default): let every connection through; your
                                                 rules and mode are kept, just paused
                                               block: block all network traffic in and out (traffic
                                                 that stays on this PC still works)
                                               off: end panic, your rules apply again
                                               remove: delete every CrioFire rule (cannot be undone)
          criofire resume                      Same as: criofire panic off
          criofire uninstall [--remove-data]   Remove all rules and unregister CrioFire
                                               (--remove-data also deletes %ProgramData%\criofire)
          criofire setup [--mode <mode>] [--allow-running]
                                               Used by the installer: register CrioFire and set the
                                               starting mode without asking
          criofire --version

        install and uninstall need an administrator prompt. Everything else also works from a
        normal prompt while the criofire service runs (changing rules then needs CrioFire's
        installed command line, or an administrator prompt).
        """;

    private static Command ParseImport(string verb, string[] rest, out string? error)
    {
        error = null;
        string? file = null;
        bool replace = false, dryRun = false, withMode = false;
        foreach (var arg in rest)
        {
            switch (arg.ToLowerInvariant())
            {
                case "--replace" when verb == "import":
                    replace = true;
                    break;
                case "--with-mode" when verb == "import":
                    withMode = true;
                    break;
                case "--dry-run":
                    dryRun = true;
                    break;
                default:
                    if (arg.StartsWith("--", StringComparison.Ordinal) || file is not null)
                    {
                        error = verb == "import"
                            ? "Usage: criofire import <file.json> [--replace] [--dry-run] [--with-mode]"
                            : "Usage: criofire restore <backup> [--dry-run]";
                        return new Command(CommandKind.Help);
                    }

                    file = arg;
                    break;
            }
        }

        if (file is null)
        {
            error = verb == "import" ? "Give the rules file to import." : "Give a backup name from 'criofire backups'.";
            return new Command(CommandKind.Help);
        }

        return new Command(verb == "import" ? CommandKind.Import : CommandKind.Restore, FilePath: file, Replace: replace, DryRun: dryRun, WithMode: withMode);
    }

    public static Command Parse(IReadOnlyList<string> args, out string? error)
    {
        error = null;
        if (args.Count == 0)
        {
            return new Command(CommandKind.Help);
        }

        var verb = args[0].ToLowerInvariant();
        var rest = args.Skip(1).ToArray();

        switch (verb)
        {
            case "help" or "-h" or "--help" or "/?":
                return new Command(CommandKind.Help);
            case "--version" or "version":
                return new Command(CommandKind.Version);
            case "uninstall" when rest.Length == 1 && rest[0].Equals("--remove-data", StringComparison.OrdinalIgnoreCase):
                return new Command(CommandKind.Uninstall, RemoveData: true);
            case "setup":
                return ParseSetup(rest, out error);
            case "panic":
            case "resume":
                return ParsePanic(verb, rest, out error);
            case "status":
            case "install":
            case "uninstall":
            case "list":
                if (rest.Length != 0)
                {
                    error = $"'{verb}' takes no arguments.";
                    return new Command(CommandKind.Help);
                }

                return new Command(verb switch
                {
                    "status" => CommandKind.Status,
                    "install" => CommandKind.Install,
                    "uninstall" => CommandKind.Uninstall,
                    _ => CommandKind.List,
                });
            case "block":
            case "unblock":
            case "allow":
                return ParseAppCommand(verb switch { "block" => CommandKind.Block, "allow" => CommandKind.Allow, _ => CommandKind.Unblock }, rest, out error);
            case "mode":
                return ParseMode(rest, out error);
            case "events":
                return ParseEvents(rest, out error);
            case "allowed":
                return ParseAllowed(rest, out error);
            case "auto":
                if (rest.Length == 0)
                {
                    return new Command(CommandKind.AutoShow);
                }

                if (rest.Length == 2 && AutoRulePolicy.IsKnown(rest[0]) && rest[1].ToLowerInvariant() is "on" or "off")
                {
                    return new Command(CommandKind.AutoSet, AutoRule: rest[0].ToLowerInvariant(), Enabled: rest[1].Equals("on", StringComparison.OrdinalIgnoreCase));
                }

                error = "Usage: criofire auto [svchost|system|lan on|off]";
                return new Command(CommandKind.Help);
            case "export":
                if (rest.Length != 1)
                {
                    error = "Usage: criofire export <file.json>";
                    return new Command(CommandKind.Help);
                }

                return new Command(CommandKind.Export, FilePath: rest[0]);
            case "import":
            case "restore":
                return ParseImport(verb, rest, out error);
            case "enroll":
                if (rest.Length == 2 || (rest.Length == 4 && rest[2].Equals("--fingerprint", StringComparison.OrdinalIgnoreCase)))
                {
                    return new Command(CommandKind.Enroll, Server: rest[0], Token: rest[1], Fingerprint: rest.Length == 4 ? rest[3] : null);
                }

                error = "Usage: criofire enroll <server> <code> [--fingerprint <sha256>]";
                return new Command(CommandKind.Help);
            case "unenroll":
            case "server":
                if (rest.Length != 0)
                {
                    error = $"'{verb}' takes no arguments.";
                    return new Command(CommandKind.Help);
                }

                return new Command(verb == "server" ? CommandKind.Server : CommandKind.Unenroll);
            case "license":
                if (rest.Length == 0)
                {
                    return new Command(CommandKind.License);
                }

                if (rest.Length == 1)
                {
                    return rest[0].Equals("--remove", StringComparison.OrdinalIgnoreCase)
                        ? new Command(CommandKind.License, FilePath: string.Empty, All: true)
                        : new Command(CommandKind.License, FilePath: rest[0], All: true);
                }

                error = "Usage: criofire license [<key>|--remove]";
                return new Command(CommandKind.Help);
            case "protection":
                if (rest.Length == 0)
                {
                    return new Command(CommandKind.Protection);
                }

                if (rest.Length == 1 && rest[0].ToLowerInvariant() is "on" or "off")
                {
                    return new Command(CommandKind.Protection, Enabled: rest[0].Equals("on", StringComparison.OrdinalIgnoreCase), All: true);
                }

                error = "Usage: criofire protection [on|off]";
                return new Command(CommandKind.Help);
            case "request" when rest.Length == 2:
                // Used by the app: one API request, approved by the user (UAC). Not in the usage text.
                return new Command(CommandKind.Request, AppPath: rest[0], FilePath: rest[1]);
            case "usage":
                if (rest.Length == 0)
                {
                    return new Command(CommandKind.DataUsed, FilePath: "today");
                }

                if (rest.Length == 1 && rest[0].Equals("--reset", StringComparison.OrdinalIgnoreCase))
                {
                    return new Command(CommandKind.DataUsed, Replace: true);
                }

                if (rest.Length == 1 && rest[0].ToLowerInvariant() is "today" or "7d" or "30d")
                {
                    return new Command(CommandKind.DataUsed, FilePath: rest[0].ToLowerInvariant());
                }

                error = "Usage: criofire usage [today|7d|30d|--reset]";
                return new Command(CommandKind.Help);
            case "domains":
                if (rest.Length != 0)
                {
                    error = "'domains' takes no arguments.";
                    return new Command(CommandKind.Help);
                }

                return new Command(CommandKind.Domains);
            case "backups":
                if (rest.Length != 0)
                {
                    error = "'backups' takes no arguments.";
                    return new Command(CommandKind.Help);
                }

                return new Command(CommandKind.Backups);
            case "changed":
                if (rest.Length != 0)
                {
                    error = "'changed' takes no arguments.";
                    return new Command(CommandKind.Help);
                }

                return new Command(CommandKind.Changed);
            case "trust":
                if (rest.Length != 1 || rest[0].StartsWith("--", StringComparison.Ordinal))
                {
                    error = "Usage: criofire trust <app.exe> (a program from 'criofire changed').";
                    return new Command(CommandKind.Help);
                }

                return new Command(CommandKind.Trust, AppPath: rest[0]);
            case "remove":
                if (rest.Length != 1 || !ulong.TryParse(rest[0], out var id))
                {
                    error = "Usage: criofire remove <filter-id> (a number from 'criofire list').";
                    return new Command(CommandKind.Help);
                }

                return new Command(CommandKind.Remove, FilterId: id);
            default:
                error = $"Unknown command '{args[0]}'.";
                return new Command(CommandKind.Help);
        }
    }

    private static Command ParseMode(string[] rest, out string? error)
    {
        error = null;
        if (rest.Length == 0)
        {
            return new Command(CommandKind.ModeShow);
        }

        if (!FilterDescriptions.TryParseMode(rest[0], out var mode))
        {
            error = $"Unknown mode '{rest[0]}'. Use learning, ask or allowlist.";
            return new Command(CommandKind.Help);
        }

        var yes = false;
        var allowRunning = false;
        foreach (var option in rest.Skip(1))
        {
            switch (option.ToLowerInvariant())
            {
                case "--yes":
                    yes = true;
                    break;
                case "--allow-running":
                    allowRunning = true;
                    break;
                default:
                    error = "Usage: criofire mode <learning|ask|allowlist> [--allow-running] [--yes]";
                    return new Command(CommandKind.Help);
            }
        }

        return new Command(CommandKind.ModeSet, Mode: mode, Yes: yes, AllowRunning: allowRunning);
    }

    private static Command ParseSetup(string[] rest, out string? error)
    {
        error = null;
        var mode = FirewallMode.Learning;
        var allowRunning = false;
        for (var i = 0; i < rest.Length; i++)
        {
            switch (rest[i].ToLowerInvariant())
            {
                case "--mode" when i + 1 < rest.Length && FilterDescriptions.TryParseMode(rest[i + 1], out var m):
                    mode = m;
                    i++;
                    break;
                case "--allow-running":
                    allowRunning = true;
                    break;
                default:
                    error = "Usage: criofire setup [--mode learning|ask|allowlist] [--allow-running]";
                    return new Command(CommandKind.Help);
            }
        }

        return new Command(CommandKind.Setup, Mode: mode, AllowRunning: allowRunning, Yes: true);
    }

    private static Command ParseEvents(string[] rest, out string? error)
    {
        error = null;
        var minutes = 10;
        var all = false;
        for (var i = 0; i < rest.Length; i++)
        {
            switch (rest[i].ToLowerInvariant())
            {
                case "--all":
                    all = true;
                    break;
                case "--minutes" when i + 1 < rest.Length && int.TryParse(rest[i + 1], out var m) && m is > 0 and <= 10080:
                    minutes = m;
                    i++;
                    break;
                default:
                    error = "Usage: criofire events [--minutes N] [--all]   (N from 1 to 10080)";
                    return new Command(CommandKind.Help);
            }
        }

        return new Command(CommandKind.Events, Minutes: minutes, All: all);
    }

    private static Command ParsePanic(string verb, string[] rest, out string? error)
    {
        error = null;
        if (verb == "resume")
        {
            if (rest.Length == 0)
            {
                return new Command(CommandKind.Panic, PanicAction: "off");
            }
        }
        else if (rest.Length == 0)
        {
            return new Command(CommandKind.Panic, PanicAction: "allow");
        }
        else if (rest.Length == 1 && rest[0].ToLowerInvariant() is var action
                 && (action == "remove" || FilterDescriptions.TryParsePanic(action, out _)))
        {
            return new Command(CommandKind.Panic, PanicAction: action == "remove" ? "remove" : FilterDescriptions.PanicText(Parse(action)));
        }

        error = "Usage: criofire panic [allow|block|off|remove]   or   criofire resume";
        return new Command(CommandKind.Help);

        static PanicState Parse(string text) => FilterDescriptions.TryParsePanic(text, out var s) ? s : PanicState.Off;
    }

    private static Command ParseAllowed(string[] rest, out string? error)
    {
        error = null;
        var minutes = 60;
        var local = false;
        for (var i = 0; i < rest.Length; i++)
        {
            switch (rest[i].ToLowerInvariant())
            {
                case "--local":
                    local = true;
                    break;
                case "--minutes" when i + 1 < rest.Length && int.TryParse(rest[i + 1], out var m) && m is > 0 and <= 43200:
                    minutes = m;
                    i++;
                    break;
                default:
                    error = "Usage: criofire allowed [--minutes N] [--local]   (N from 1 to 43200)";
                    return new Command(CommandKind.Help);
            }
        }

        return new Command(CommandKind.Allowed, Minutes: minutes, All: local);
    }

    private static Command ParseAppCommand(CommandKind kind, string[] rest, out string? error)
    {
        error = null;
        string? path = null;
        string? service = null;
        string? domain = null;
        TrafficDirection? direction = null;

        int? expires = null;
        NetworkProfiles? networks = null;
        string? ports = null;
        string? addresses = null;
        NetProtocol? protocol = null;
        for (var i = 0; i < rest.Length; i++)
        {
            var arg = rest[i];
            if (kind != CommandKind.Unblock && (arg.Equals("--port", StringComparison.OrdinalIgnoreCase) || arg.Equals("--addr", StringComparison.OrdinalIgnoreCase)))
            {
                if (i + 1 >= rest.Length || rest[i + 1].StartsWith("--", StringComparison.Ordinal))
                {
                    error = $"{arg} needs a value, e.g. --port 443 or --addr 10.0.0.0/8.";
                    return new Command(CommandKind.Help);
                }

                if (arg.Equals("--port", StringComparison.OrdinalIgnoreCase))
                {
                    ports = ports is null ? rest[i + 1] : ports + "," + rest[i + 1];
                }
                else
                {
                    addresses = addresses is null ? rest[i + 1] : addresses + "," + rest[i + 1];
                }

                i++;
                continue;
            }

            if (kind != CommandKind.Unblock && (arg.Equals("--tcp", StringComparison.OrdinalIgnoreCase) || arg.Equals("--udp", StringComparison.OrdinalIgnoreCase)))
            {
                var p = arg.Equals("--tcp", StringComparison.OrdinalIgnoreCase) ? NetProtocol.Tcp : NetProtocol.Udp;
                if (protocol is not null && protocol != p)
                {
                    error = "Give only one of --tcp or --udp (leave both out for any).";
                    return new Command(CommandKind.Help);
                }

                protocol = p;
                continue;
            }

            if (arg.Equals("--domain", StringComparison.OrdinalIgnoreCase))
            {
                if (i + 1 >= rest.Length)
                {
                    error = "--domain needs a domain name, e.g. --domain example.com.";
                    return new Command(CommandKind.Help);
                }

                domain = DomainNames.Normalize(rest[i + 1], out error);
                if (domain is null)
                {
                    return new Command(CommandKind.Help);
                }

                i++;
                continue;
            }

            if (arg.Equals("--service", StringComparison.OrdinalIgnoreCase))
            {
                if (i + 1 >= rest.Length || !ServiceRule.IsValidName(rest[i + 1]))
                {
                    error = "--service needs a service name, e.g. --service Dnscache (see the Name column of services.msc).";
                    return new Command(CommandKind.Help);
                }

                service = rest[i + 1];
                i++;
                continue;
            }

            if ((arg.Equals("--networks", StringComparison.OrdinalIgnoreCase) || arg.Equals("--network", StringComparison.OrdinalIgnoreCase)) && kind != CommandKind.Unblock)
            {
                if (i + 1 >= rest.Length || !NetworkScope.TryParse(rest[i + 1], out var parsed))
                {
                    error = "--networks needs any, or a list of domain, private and public, e.g. --networks public or --networks domain,private.";
                    return new Command(CommandKind.Help);
                }

                networks = parsed;
                i++;
                continue;
            }

            if (arg.Equals("--for", StringComparison.OrdinalIgnoreCase) && kind != CommandKind.Unblock)
            {
                if (i + 1 >= rest.Length || !int.TryParse(rest[i + 1], out var minutes) || minutes is < 1 or > 10080)
                {
                    error = "--for needs a number of minutes from 1 to 10080.";
                    return new Command(CommandKind.Help);
                }

                expires = minutes;
                i++;
                continue;
            }

            TrafficDirection? flag = arg.ToLowerInvariant() switch
            {
                "--out" => TrafficDirection.Outbound,
                "--in" => TrafficDirection.Inbound,
                "--both" => TrafficDirection.Both,
                _ => null,
            };

            if (flag is not null)
            {
                if (direction is not null)
                {
                    error = "Give only one of --out, --in or --both.";
                    return new Command(CommandKind.Help);
                }

                direction = flag;
            }
            else if (arg.StartsWith("--", StringComparison.Ordinal))
            {
                error = $"Unknown option '{arg}'.";
                return new Command(CommandKind.Help);
            }
            else if (path is null)
            {
                path = arg;
            }
            else
            {
                error = "Give exactly one program path. Put paths with spaces in quotes.";
                return new Command(CommandKind.Help);
            }
        }

        if (domain is not null)
        {
            if (service is not null || ports is not null || addresses is not null || protocol is not null || expires is not null || direction is TrafficDirection.Inbound or TrafficDirection.Both)
            {
                error = "--domain cannot be combined with --service, --port, --addr, --tcp, --udp, --for, --in or --both (domain rules are for outgoing connections).";
                return new Command(CommandKind.Help);
            }

            return new Command(kind, path, TrafficDirection.Outbound, Networks: networks ?? NetworkProfiles.Any, Domain: domain);
        }

        if (service is not null)
        {
            if (path is not null || ports is not null || addresses is not null || protocol is not null || expires is not null)
            {
                error = "--service cannot be combined with a program path, --port, --addr, --tcp, --udp or --for.";
                return new Command(CommandKind.Help);
            }

            return new Command(kind, Direction: direction ?? (kind == CommandKind.Unblock ? TrafficDirection.Both : TrafficDirection.Outbound), Service: service,
                Networks: networks ?? NetworkProfiles.Any);
        }

        if (ports is not null || addresses is not null || protocol is not null)
        {
            if (expires is not null)
            {
                error = "--for works with program rules only, not with --port, --addr, --tcp or --udp.";
                return new Command(CommandKind.Help);
            }

            var rule = NetRule.Create(
                kind == CommandKind.Block ? RuleAction.Block : RuleAction.Allow,
                direction ?? TrafficDirection.Outbound,
                protocol ?? NetProtocol.Any,
                ports,
                addresses,
                path,
                out error,
                networks ?? NetworkProfiles.Any);
            return rule is null ? new Command(CommandKind.Help) : new Command(kind, path, rule.Direction, Net: rule, Networks: rule.Networks);
        }

        if (path is null)
        {
            error = $"Usage: criofire {kind.ToString().ToLowerInvariant()} <app.exe> [--out|--in|--both]";
            return new Command(CommandKind.Help);
        }

        var defaultDirection = kind == CommandKind.Unblock ? TrafficDirection.Both : TrafficDirection.Outbound;
        return new Command(kind, path, direction ?? defaultDirection, ExpiresMinutes: expires, Networks: networks ?? NetworkProfiles.Any);
    }
}
