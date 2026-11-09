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

        case CommandKind.Unblock:
            var removed = engine.RemoveAppRules(command.AppPath!, command.Direction);
            Console.WriteLine(removed == 0 ? "No CrioFire rules matched that program." : $"Removed {removed} filters.");
            return 0;

        case CommandKind.Remove:
            engine.RemoveFilter(command.FilterId);
            Console.WriteLine($"Removed filter {command.FilterId}.");
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

static void EnsureInstalled(WfpEngine engine)
{
    if (!engine.IsInstalled())
    {
        engine.Install();
    }
}
