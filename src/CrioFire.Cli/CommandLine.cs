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
}

/// <param name="Minutes">events: how far back to look.</param>
/// <param name="All">events: include drops by other firewalls, not only CrioFire's.</param>
/// <param name="Mode">mode: the mode to switch to.</param>
/// <param name="Yes">mode: keep the new mode without the "is your network still working?" check.</param>
/// <param name="AllowRunning">mode: also allow every program running right now.</param>
/// <param name="ExpiresMinutes">allow/block --for N: the rule is removed again after N minutes.</param>
/// <param name="Net">allow/block with --port, --addr, --tcp or --udp: a network rule (program optional).</param>
/// <param name="RemoveData">uninstall --remove-data: also delete %ProgramData%\criofire (logs, temporary rules).</param>
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
    bool RemoveData = false);

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
          criofire mode                        Show the current mode
          criofire mode <learning|ask|allowlist> [--allow-running] [--yes]
                                               learning: programs without a rule may connect
                                               ask / allowlist: they are blocked (outbound; loopback and
                                               Windows services stay allowed)
                                               --allow-running: first allow every program running now
                                               Asks you to confirm the network still works within 60 s,
                                               otherwise switches back (--yes skips the check)
          criofire remove <filter-id>          Remove one CrioFire filter by ID
          criofire events [--minutes N] [--all]
                                               Show connections CrioFire blocked (default: last 10 minutes;
                                               --all also shows drops by other firewalls)
          criofire panic                       Recovery: remove every CrioFire rule at once
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
            case "status":
            case "install":
            case "uninstall":
            case "list":
            case "panic":
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
                    "list" => CommandKind.List,
                    _ => CommandKind.Panic,
                });
            case "block":
            case "unblock":
            case "allow":
                return ParseAppCommand(verb switch { "block" => CommandKind.Block, "allow" => CommandKind.Allow, _ => CommandKind.Unblock }, rest, out error);
            case "mode":
                return ParseMode(rest, out error);
            case "events":
                return ParseEvents(rest, out error);
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

    private static Command ParseAppCommand(CommandKind kind, string[] rest, out string? error)
    {
        error = null;
        string? path = null;
        TrafficDirection? direction = null;

        int? expires = null;
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
                out error);
            return rule is null ? new Command(CommandKind.Help) : new Command(kind, path, rule.Direction, Net: rule);
        }

        if (path is null)
        {
            error = $"Usage: criofire {kind.ToString().ToLowerInvariant()} <app.exe> [--out|--in|--both]";
            return new Command(CommandKind.Help);
        }

        var defaultDirection = kind == CommandKind.Unblock ? TrafficDirection.Both : TrafficDirection.Outbound;
        return new Command(kind, path, direction ?? defaultDirection, ExpiresMinutes: expires);
    }
}
