using System.Reflection;
using System.Security.Principal;
using CrioFire.Cli;
using CrioFire.Core;
using CrioFire.Core.Api;

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
    // install and uninstall always talk to the filtering engine directly (administrator only).
    if (command.Kind is CommandKind.Install or CommandKind.Uninstall)
    {
        using var engine = WfpEngine.Open();
        if (command.Kind == CommandKind.Install)
        {
            engine.Install();
            Console.WriteLine("CrioFire is registered with the Windows Filtering Platform.");
        }
        else
        {
            engine.Uninstall();
            Console.WriteLine("All CrioFire rules removed and CrioFire unregistered.");
        }

        return 0;
    }

    // Everything else goes through the API: in-process when elevated (works even if the service
    // is stopped, e.g. for recovery), otherwise through the criofire service.
    using var api = Backend.Connect();
    if (api is null)
    {
        Console.Error.WriteLine("The CrioFire service is not running. Start it (sc start criofire) or use an administrator terminal.");
        return 3;
    }

    return Run(api, command);
}
catch (WfpException ex)
{
    Console.Error.WriteLine(ex.Message);
    return ex.IsAccessDenied ? 5 : 1;
}
catch (Exception ex) when (ex is IOException or InvalidOperationException or PlatformNotSupportedException or ArgumentException)
{
    Console.Error.WriteLine(ex.Message);
    return 1;
}

static int Run(Backend api, Command command)
{
    switch (command.Kind)
    {
        case CommandKind.Status:
        {
            var status = api.Call(new ApiRequest { Op = ApiOps.Status }).Status!;
            if (!status.Installed)
            {
                Console.WriteLine("CrioFire is not installed. Run: criofire install");
                return 1;
            }

            Console.WriteLine($"CrioFire is installed ({api.Description}). Mode: {status.Mode}. Active filters: {status.FilterCount}");
            return 0;
        }

        case CommandKind.List:
        {
            var rules = api.Call(new ApiRequest { Op = ApiOps.List }).Rules!;
            if (rules.Count == 0)
            {
                Console.WriteLine("No CrioFire rules.");
                return 0;
            }

            Console.WriteLine($"{"Filter ID",-12} {"Action",-7} {"Kind",-13} {"Layer",-14} Program");
            foreach (var r in rules.OrderBy(r => r.Kind, StringComparer.Ordinal).ThenBy(r => r.App, StringComparer.OrdinalIgnoreCase).ThenBy(r => r.FilterId))
            {
                Console.WriteLine($"{r.FilterId,-12} {r.Action ?? "?",-7} {r.Kind,-13} {r.Layer ?? "?",-14} {r.App ?? r.Name}");
            }

            return 0;
        }

        case CommandKind.Block or CommandKind.Allow:
        {
            var path = Path.GetFullPath(command.AppPath!);
            var action = command.Kind == CommandKind.Block ? "block" : "allow";
            var result = api.Call(new ApiRequest { Op = ApiOps.SetRule, App = path, Action = action, Direction = RuleDescription.DirectionText(command.Direction) });
            Console.WriteLine($"{(action == "block" ? "Blocked" : "Allowed")} {RuleDescription.DirectionText(command.Direction)} traffic for {path} ({result.Count} filters).");
            if (action == "block")
            {
                Console.WriteLine($"Undo with: criofire unblock \"{path}\"");
            }

            return 0;
        }

        case CommandKind.Unblock:
        {
            var result = api.Call(new ApiRequest { Op = ApiOps.RemoveRules, App = Path.GetFullPath(command.AppPath!), Direction = RuleDescription.DirectionText(command.Direction) });
            Console.WriteLine(result.Count == 0 ? "No CrioFire rules matched that program." : $"Removed {result.Count} filters.");
            return 0;
        }

        case CommandKind.Remove:
            api.Call(new ApiRequest { Op = ApiOps.RemoveFilter, FilterId = command.FilterId });
            Console.WriteLine($"Removed filter {command.FilterId}.");
            return 0;

        case CommandKind.Events:
        {
            var events = api.Call(new ApiRequest { Op = ApiOps.Events, Minutes = command.Minutes, All = command.All }).Events!;
            if (events.Count == 0)
            {
                Console.WriteLine($"No blocked connections in the last {command.Minutes} minutes.");
                return 0;
            }

            Console.WriteLine($"{"Time (local)",-20} {"By",-9} {"Dir",-4} {"Proto",-6} {"Remote",-40} Program");
            foreach (var e in events)
            {
                Console.WriteLine($"{e.TimeUtc.ToLocalTime():yyyy-MM-dd HH:mm:ss} {(e.CrioFire ? "CrioFire" : "other"),-9} {e.Direction ?? "?",-4} {e.Protocol,-6} {e.Remote ?? "?",-40} {e.App ?? "?"}");
            }

            return 0;
        }

        case CommandKind.ModeShow:
            Console.WriteLine($"Mode: {api.Call(new ApiRequest { Op = ApiOps.Status }).Status!.Mode}");
            return 0;

        case CommandKind.ModeSet:
            return SetMode(api, command);

        case CommandKind.Panic:
        {
            var result = api.Call(new ApiRequest { Op = ApiOps.Panic });
            Console.WriteLine($"Recovery done: removed {result.Count} CrioFire filters. Network access is back to Windows' own rules.");
            return 0;
        }

        default:
            Console.Error.WriteLine(CommandLine.Usage);
            return 2;
    }
}

static int SetMode(Backend api, Command command)
{
    var previous = api.Call(new ApiRequest { Op = ApiOps.Status }).Status!.Mode;
    var running = command.AllowRunning ? RunningPrograms.Paths() : [];
    var text = FilterDescriptions.ModeText(command.Mode);
    api.Call(new ApiRequest { Op = ApiOps.SetMode, Mode = text, Apps = running });
    if (running.Count > 0)
    {
        Console.WriteLine($"Allowed the running programs that had no rule yet ({running.Count} checked).");
    }

    if (command.Mode == FirewallMode.Learning || command.Yes)
    {
        Console.WriteLine($"Mode: {text}");
        return 0;
    }

    // Blocking mode: keep it only if the user confirms the network still works.
    if (Console.IsInputRedirected)
    {
        api.Call(new ApiRequest { Op = ApiOps.SetMode, Mode = previous });
        Console.Error.WriteLine($"Switched back to {previous}: confirm interactively, or pass --yes.");
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

    api.Call(new ApiRequest { Op = ApiOps.SetMode, Mode = previous });
    Console.WriteLine();
    Console.WriteLine($"No confirmation: switched back to {previous}.");
    return 1;
}

/// <summary>Either the in-process API (elevated) or the service's pipe (not elevated).</summary>
internal sealed class Backend : IDisposable
{
    private readonly WfpEngine? _engine;
    private readonly ApiHandler? _handler;
    private readonly CrioFireClient? _client;

    private Backend(WfpEngine engine)
    {
        _engine = engine;
        _handler = new ApiHandler(engine);
        Description = "direct, administrator";
    }

    private Backend(CrioFireClient client)
    {
        _client = client;
        Description = "through the criofire service";
    }

    public string Description { get; }

    public static Backend? Connect()
    {
        if (IsElevated())
        {
            return new Backend(WfpEngine.Open());
        }

        var client = CrioFireClient.TryConnect();
        return client is null ? null : new Backend(client);
    }

    /// <summary>Sends a request; throws <see cref="InvalidOperationException"/> with the service's message on failure.</summary>
    public ApiResponse Call(ApiRequest request)
    {
        var response = _handler is not null ? _handler.Handle(request, canWrite: true) : _client!.Send(request);
        return response.Ok ? response : throw new InvalidOperationException(response.Error ?? "The request failed.");
    }

    public void Dispose()
    {
        _engine?.Dispose();
        _client?.Dispose();
    }

    private static bool IsElevated()
    {
        if (!OperatingSystem.IsWindows())
        {
            return false;
        }

        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }
}
