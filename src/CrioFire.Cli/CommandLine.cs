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
}

/// <param name="Minutes">events: how far back to look.</param>
/// <param name="All">events: include drops by other firewalls, not only CrioFire's.</param>
/// <param name="Mode">mode: the mode to switch to.</param>
/// <param name="Yes">mode: keep the new mode without the "is your network still working?" check.</param>
/// <param name="AllowRunning">mode: also allow every program running right now.</param>
/// <param name="ExpiresMinutes">allow/block --for N: the rule is removed again after N minutes.</param>
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
    int? ExpiresMinutes = null);

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
          criofire uninstall                   Remove all rules and unregister CrioFire
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
        for (var i = 0; i < rest.Length; i++)
        {
            var arg = rest[i];
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

        if (path is null)
        {
            error = $"Usage: criofire {kind.ToString().ToLowerInvariant()} <app.exe> [--out|--in|--both]";
            return new Command(CommandKind.Help);
        }

        var defaultDirection = kind == CommandKind.Unblock ? TrafficDirection.Both : TrafficDirection.Outbound;
        return new Command(kind, path, direction ?? defaultDirection, ExpiresMinutes: expires);
    }
}
