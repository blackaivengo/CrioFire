using System.Reflection;
using CrioFire.Cli;
using CrioFire.Core;

var command = CommandLine.Parse(args, out var parseError);
if (parseError is not null)
{
    Console.Error.WriteLine(parseError);
    Console.Error.WriteLine();
    Console.Error.WriteLine(CommandLine.Usage);
    return 2;
}

switch (command.Kind)
{
    case CommandKind.Help:
        Console.WriteLine(CommandLine.Usage);
        return 0;
    case CommandKind.Version:
        var version = Assembly.GetExecutingAssembly()
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? "unknown";
        Console.WriteLine($"criofire {version}");
        return 0;
}

try
{
    using var engine = WfpEngine.Open();

    switch (command.Kind)
    {
        case CommandKind.Status:
            if (!engine.IsInstalled())
            {
                Console.WriteLine("CrioFire is not installed. Run: criofire install");
                return 1;
            }

            Console.WriteLine($"CrioFire is installed. Active filters: {engine.ListFilters().Count}");
            return 0;

        case CommandKind.Install:
            engine.Install();
            Console.WriteLine("CrioFire is registered with the Windows Filtering Platform.");
            return 0;

        case CommandKind.Uninstall:
            engine.Uninstall();
            Console.WriteLine("All CrioFire rules removed and CrioFire unregistered.");
            return 0;

        case CommandKind.List:
            var filters = engine.ListFilters();
            if (filters.Count == 0)
            {
                Console.WriteLine("No CrioFire rules.");
                return 0;
            }

            Console.WriteLine($"{"Filter ID",-12} {"Action",-7} {"Layer",-14} Program");
            foreach (var f in filters.OrderBy(f => f.Rule?.AppPath, StringComparer.OrdinalIgnoreCase).ThenBy(f => f.FilterId))
            {
                var action = f.Rule is null ? "?" : RuleDescription.ActionText(f.Rule.Action);
                Console.WriteLine($"{f.FilterId,-12} {action,-7} {f.Layer?.Name ?? "?",-14} {f.Rule?.AppPath ?? f.Name}");
            }

            return 0;

        case CommandKind.Block:
            EnsureInstalled(engine);
            var ids = engine.SetAppRule(command.AppPath!, RuleAction.Block, command.Direction);
            Console.WriteLine($"Blocked {RuleDescription.DirectionText(command.Direction)} traffic for {Path.GetFullPath(command.AppPath!)} ({ids.Count} filters).");
            Console.WriteLine("Undo with: criofire unblock \"" + Path.GetFullPath(command.AppPath!) + "\"");
            return 0;

        case CommandKind.Allow:
            EnsureInstalled(engine);
            var allowIds = engine.SetAppRule(command.AppPath!, RuleAction.Allow, command.Direction);
            Console.WriteLine($"Allowed {RuleDescription.DirectionText(command.Direction)} traffic for {Path.GetFullPath(command.AppPath!)} ({allowIds.Count} filters).");
            return 0;

        case CommandKind.ModeShow:
            Console.WriteLine($"Mode: {FilterDescriptions.ModeText(engine.GetMode())}");
            return 0;

        case CommandKind.ModeSet:
            return SetMode(engine, command);

        case CommandKind.Unblock:
            var removed = engine.RemoveAppRules(command.AppPath!, command.Direction);
            Console.WriteLine(removed == 0 ? "No CrioFire rules matched that program." : $"Removed {removed} filters.");
            return 0;

        case CommandKind.Remove:
            engine.RemoveFilter(command.FilterId);
            Console.WriteLine($"Removed filter {command.FilterId}.");
            return 0;

        case CommandKind.Events:
            var events = engine.ReadBlockedConnections(DateTime.UtcNow.AddMinutes(-command.Minutes), crioFireOnly: !command.All);
            if (events.Count == 0)
            {
                Console.WriteLine($"No blocked connections in the last {command.Minutes} minutes.");
                return 0;
            }

            Console.WriteLine($"{"Time (local)",-20} {"By",-9} {"Dir",-4} {"Proto",-6} {"Remote",-40} Program");
            foreach (var e in events)
            {
                var by = e.IsCrioFire ? "CrioFire" : "other";
                var dir = e.Direction switch { TrafficDirection.Outbound => "out", TrafficDirection.Inbound => "in", _ => "?" };
                Console.WriteLine($"{e.TimeUtc.ToLocalTime():yyyy-MM-dd HH:mm:ss} {by,-9} {dir,-4} {e.ProtocolName,-6} {e.Remote?.ToString() ?? "?",-40} {e.AppPath ?? "?"}");
            }

            return 0;

        case CommandKind.Panic:
            var count = engine.RemoveAllFilters();
            Console.WriteLine($"Recovery done: removed {count} CrioFire filters. Network access is back to Windows' own rules.");
            return 0;

        default:
            Console.Error.WriteLine(CommandLine.Usage);
            return 2;
    }
}
catch (WfpException ex)
{
    Console.Error.WriteLine(ex.Message);
    return ex.IsAccessDenied ? 5 : 1;
}
catch (Exception ex) when (ex is FileNotFoundException or InvalidOperationException or PlatformNotSupportedException or ArgumentException)
{
    Console.Error.WriteLine(ex.Message);
    return 1;
}

static int SetMode(WfpEngine engine, Command command)
{
    EnsureInstalled(engine);
    var previous = engine.GetMode();
    var running = command.AllowRunning ? RunningPrograms.Paths() : [];
    engine.SetMode(command.Mode, running);
    var text = FilterDescriptions.ModeText(command.Mode);
    if (running.Count > 0)
    {
        Console.WriteLine($"Allowed {running.Count} running programs (those without a rule already).");
    }

    if (command.Mode == FirewallMode.Learning || command.Yes)
    {
        Console.WriteLine($"Mode: {text}");
        return 0;
    }

    // Blocking mode: keep it only if the user confirms the network still works.
    if (Console.IsInputRedirected)
    {
        engine.SetMode(previous);
        Console.Error.WriteLine($"Switched back to {FilterDescriptions.ModeText(previous)}: confirm interactively, or pass --yes.");
        return 1;
    }

    Console.WriteLine($"Mode is now {text}. Programs without an allow rule can no longer connect out.");
    Console.Write("Is your network still working? Type 'yes' within 60 seconds to keep it: ");
    var answer = Task.Run(Console.ReadLine);
    if (answer.Wait(TimeSpan.FromSeconds(60)) && string.Equals(answer.Result?.Trim(), "yes", StringComparison.OrdinalIgnoreCase))
    {
        Console.WriteLine($"Keeping {text}. To undo: criofire mode learning   (or criofire panic)");
        return 0;
    }

    engine.SetMode(previous);
    Console.WriteLine();
    Console.WriteLine($"No confirmation: switched back to {FilterDescriptions.ModeText(previous)}.");
    return 1;
}

static void EnsureInstalled(WfpEngine engine)
{
    if (!engine.IsInstalled())
    {
        engine.Install();
    }
}
