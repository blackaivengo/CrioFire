using CrioFire.Core;

namespace CrioFire.Cli;

internal enum CommandKind
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
}

internal sealed record Command(CommandKind Kind, string? AppPath = null, TrafficDirection Direction = TrafficDirection.Outbound, ulong FilterId = 0);

/// <summary>Parses criofire.exe arguments. Pure logic, no Windows calls, so it is unit-tested.</summary>
internal static class CommandLine
{
    public const string Usage = """
        CrioFire Private Firewall - command line (prototype)

        Usage:
          criofire status                      Show whether CrioFire is installed and how many rules exist
          criofire install                     Register CrioFire with the Windows Filtering Platform
          criofire list                        List CrioFire's rules
          criofire block <app.exe> [--out|--in|--both]
                                               Block one program (default: outbound)
          criofire unblock <app.exe> [--out|--in|--both]
                                               Remove CrioFire's rules for one program (default: both)
          criofire remove <filter-id>          Remove one CrioFire filter by ID
          criofire panic                       Recovery: remove every CrioFire rule at once
          criofire uninstall                   Remove all rules and unregister CrioFire
          criofire --version

        All commands except --version and help need an administrator prompt.
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
                return ParseAppCommand(verb == "block" ? CommandKind.Block : CommandKind.Unblock, rest, out error);
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

    private static Command ParseAppCommand(CommandKind kind, string[] rest, out string? error)
    {
        error = null;
        string? path = null;
        TrafficDirection? direction = null;

        foreach (var arg in rest)
        {
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
            error = $"Usage: criofire {(kind == CommandKind.Block ? "block" : "unblock")} <app.exe> [--out|--in|--both]";
            return new Command(CommandKind.Help);
        }

        var defaultDirection = kind == CommandKind.Block ? TrafficDirection.Outbound : TrafficDirection.Both;
        return new Command(kind, path, direction ?? defaultDirection);
    }
}
