using System.Globalization;
using System.IO;
using System.Windows;
using CrioFire.Core;

namespace CrioFire.App.Pages;

/// <summary>One stacked bar: "your rules" (fire) under "no rule yet" (ice). Heights in pixels.</summary>
public sealed record ChartBar(double RuleHeight, double ModeHeight, string Tip, string Label, string TotalText);

/// <summary>A row with a proportional bar, e.g. a program and its share of blocked connections.</summary>
public sealed record ShareRow(string Name, string App, string CountText, double Share)
{
    public GridLength Fill => new(Math.Max(Share, 0.001), GridUnitType.Star);

    public GridLength Rest => new(Math.Max(1 - Share, 0.001), GridUnitType.Star);
}

/// <summary>One program's data used, with its share of the total.</summary>
public sealed record UsageRow(string Program, string App, string SentText, string ReceivedText, string TotalText, double Share, string ShareText)
{
    public GridLength Fill => new(Math.Max(Share, 0.001), GridUnitType.Star);

    public GridLength Rest => new(Math.Max(1 - Share, 0.001), GridUnitType.Star);

    public static UsageRow From(AppUsage usage, long total, CultureInfo culture)
    {
        ArgumentNullException.ThrowIfNull(usage);
        var share = total <= 0 ? 0 : (double)usage.Total / total;
        return new(
            DataSize.ProgramName(usage.App),
            usage.App == AppUsage.UnknownApp ? L.T("Processes that ended within a second of using the network") : usage.App,
            DataSize.Text(usage.Sent, culture),
            DataSize.Text(usage.Received, culture),
            DataSize.Text(usage.Total, culture),
            share,
            share.ToString("P0", culture) + L.T(" of all data"));
    }
}

/// <param name="Services">The Windows services running in that process (svchost.exe), comma-separated, or empty.</param>
public sealed record LiveRow(string Program, string Path, string Local, string Remote, string Protocol, string State, int ProcessId, string Services = "")
{
    public static LiveRow From(LiveConnection c) => From(c, null);

    public static LiveRow From(LiveConnection c, IReadOnlyDictionary<int, string[]>? services)
    {
        var names = services is not null && services.TryGetValue(c.ProcessId, out var n) ? string.Join(", ", n) : string.Empty;
        var program = c.ProcessId == 4
            ? L.T("Windows kernel (System)")
            : System.IO.Path.GetFileName(c.ProcessPath) is { Length: > 0 } file ? file : $"PID {c.ProcessId}";
        return new(
            program,
            c.ProcessPath ?? L.T("(not visible to this user)"),
            c.Local.ToString(),
            c.Remote?.ToString() ?? string.Empty,
            c.ProtocolName,
            c.State,
            c.ProcessId,
            names);
    }
}

internal static class Bars
{
    /// <summary>Scales report buckets to stacked bars of at most <paramref name="height"/> pixels.</summary>
    public static List<ChartBar> From(IReadOnlyList<ReportBucket> buckets, double height, Func<ReportBucket, string> label, Func<ReportBucket, string> when)
    {
        var max = Math.Max(1, buckets.Count == 0 ? 1 : buckets.Max(b => b.Total));
        return buckets.Select(b => new ChartBar(
            b.ByRule * height / max,
            b.ByMode * height / max,
            L.T($"{when(b)}: {b.ByRule} by your rules, {b.ByMode} with no rule yet"),
            label(b),
            b.Total == 0 ? string.Empty : b.Total.ToString("N0", CultureInfo.CurrentCulture))).ToList();
    }

    public static string Name(string? path) => string.IsNullOrEmpty(path) ? "?" : (Path.GetFileName(path) is { Length: > 0 } name ? name : path);
}

public sealed record ProgramRow(string Name, string App, string CountText, double Share, string Why, string LastSeen,
    System.Windows.Media.Brush BarBrush, System.Windows.Media.Brush ChipBrush, System.Windows.Media.Brush ChipTextBrush)
{
    public GridLength Fill => new(Math.Max(Share, 0.001), GridUnitType.Star);

    public GridLength Rest => new(Math.Max(1 - Share, 0.001), GridUnitType.Star);
}

public sealed record DestinationRow(string Address, string Port, string CountText);

public sealed record ActivityRow(string Time, string Why, string Direction, string Protocol, string Remote, string Program, string? App,
    System.Windows.Media.Brush ChipBrush, System.Windows.Media.Brush ChipTextBrush);

/// <summary>A program rule on the Rules page. <see cref="Info"/> is the rule itself, for switching and removing.</summary>
public sealed record RuleRow(CrioFire.Core.Api.RuleInfo Info, string Action, string Direction, string Program, string App, string Until,
    System.Windows.Media.Brush ChipBrush, System.Windows.Media.Brush ChipTextBrush)
{
    /// <summary>Allow or Block as shown (translated); <see cref="Action"/> stays English for comparisons and sorting.</summary>
    public string ActionText => L.T(Action);

    public string FlipHint => Info.Managed ? L.T("Set by your organization; it cannot be changed on this PC.")
        : Action == "Allow" ? L.T("Allowed. Click to block it instead.") : L.T("Blocked. Click to allow it instead.");
}

public sealed record NetRuleRow(CrioFire.Core.Api.RuleInfo Info, string Action, string Direction, string Rule, string Program, string? App, ulong FilterId,
    System.Windows.Media.Brush ChipBrush, System.Windows.Media.Brush ChipTextBrush)
{
    /// <summary>Allow or Block as shown (translated); <see cref="Action"/> stays English for comparisons and sorting.</summary>
    public string ActionText => L.T(Action);

    public string FlipHint => Info.Managed ? L.T("Set by your organization; it cannot be changed on this PC.")
        : Action == "Allow" ? L.T("Allowed. Click to block it instead.") : L.T("Blocked. Click to allow it instead.");
}

/// <summary>A program or a single Windows service that was allowed to connect.</summary>
/// <param name="Service">For svchost.exe: the service(s) behind it, when known.</param>
public sealed record AllowedRow(string Name, string Detail, string? App, string? Service, string CountText, double Share, string Why, string Direction, string LastSeen,
    System.Windows.Media.Brush ChipBrush, System.Windows.Media.Brush ChipTextBrush)
{
    public GridLength Fill => new(Math.Max(Share, 0.001), GridUnitType.Star);

    public GridLength Rest => new(Math.Max(1 - Share, 0.001), GridUnitType.Star);
}

/// <summary>One line of the Activity page's "Allowed" list: allowed connections grouped by destination and reason.</summary>
public sealed record AllowedActivityRow(string Time, string Why, string Direction, string Protocol, string Remote, string CountText, string Program, string Detail,
    string? App, string? Service, System.Windows.Media.Brush ChipBrush, System.Windows.Media.Brush ChipTextBrush);

public sealed record ServiceRuleRow(CrioFire.Core.Api.RuleInfo Info, string Action, string Direction, string Service, string DisplayName,
    System.Windows.Media.Brush ChipBrush, System.Windows.Media.Brush ChipTextBrush)
{
    /// <summary>Allow or Block as shown (translated); <see cref="Action"/> stays English for comparisons and sorting.</summary>
    public string ActionText => L.T(Action);

    public string FlipHint => Info.Managed ? L.T("Set by your organization; it cannot be changed on this PC.")
        : Action == "Allow" ? L.T("Allowed. Click to block it instead.") : L.T("Blocked. Click to allow it instead.");
}

/// <summary>One of CrioFire's automatic permits or always-on behaviours, shown on the Rules page.</summary>
public sealed record AutoRuleRow(string Name, string Title, string Description, string State, bool CanSwitch, bool IsOn);

internal static class Who
{
    /// <summary>"Service: Dnscache" for a known service in svchost.exe, otherwise the program's name; plus a detail line.</summary>
    public static (string Name, string Detail) Of(string? app, string? service)
    {
        if (!string.IsNullOrEmpty(service))
        {
            return (L.T($"Service: {service}"), app ?? "svchost.exe");
        }

        if (KnownApps.IsKernel(app))
        {
            return (KnownApps.DisplayName(app), L.T("Kernel-mode traffic: file sharing, NetBIOS, ICMP…"));
        }

        if (KnownApps.IsServiceHost(app))
        {
            return (L.T("Windows services (svchost.exe)"), app!);
        }

        return (KnownApps.DisplayName(app), app ?? L.T("(unknown program)"));
    }

    public static string Direction(string? d) => d switch { "in" => L.T("Inbound"), "both" => L.T("Both"), "out" => L.T("Outbound"), _ => "?" };
}

/// <summary>A row of the Activity page: blocked or allowed connections grouped by program, destination and reason.</summary>
public sealed record TrafficRow(TrafficItem Item, string Time, string CountText, string Why, string Direction, string Remote, string PortName,
    string Program, string Detail, System.Windows.Media.Brush ChipBrush, System.Windows.Media.Brush ChipTextBrush)
{
    /// <summary>Identifies the row across refreshes (time and count change, the rest does not).</summary>
    public string Key => string.Join('|', Item.Allowed, Item.App, Item.Service, Item.Protocol, Item.Direction, Item.Remote, Item.Port, Item.Why, Item.FilterId);
}

/// <summary>One labelled line of the Activity page's details pane.</summary>
public sealed record Fact(string Label, string Value);

/// <summary>A domain rule on the Rules page.</summary>
public sealed record DomainRuleRow(CrioFire.Core.Api.DomainRuleInfo Info, string Action, string Domain, string Details,
    System.Windows.Media.Brush ChipBrush, System.Windows.Media.Brush ChipTextBrush, bool CanRemove, string RemoveHint)
{
    public string ActionText => L.T(Action);
}
