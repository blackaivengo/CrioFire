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

public sealed record LiveRow(string Program, string Path, string Local, string Remote, string Protocol, string State, int ProcessId)
{
    public static LiveRow From(LiveConnection c) => new(
        System.IO.Path.GetFileName(c.ProcessPath) ?? $"PID {c.ProcessId}",
        c.ProcessPath ?? "(not visible to this user)",
        c.Local.ToString(),
        c.Remote?.ToString() ?? string.Empty,
        c.ProtocolName,
        c.State,
        c.ProcessId);
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
            $"{when(b)}: {b.ByRule} by your rules, {b.ByMode} with no rule yet",
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

public sealed record RuleRow(string Action, string Direction, string Program, string App, string Until,
    System.Windows.Media.Brush ChipBrush, System.Windows.Media.Brush ChipTextBrush);

public sealed record NetRuleRow(string Action, string Direction, string Rule, string Program, string? App, ulong FilterId,
    System.Windows.Media.Brush ChipBrush, System.Windows.Media.Brush ChipTextBrush);
