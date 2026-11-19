namespace CrioFire.Core.Api;

/// <summary>
/// Says in plain words what a request would change. Windows' own approval prompt only names the
/// program ("CrioFire"), so any program could start CrioFire's command line with a request of its
/// own and get it approved unseen. The elevated command line shows this text and asks before it
/// does anything.
/// </summary>
public static class ApprovalText
{
    /// <summary>One or two short sentences describing the change.</summary>
    public static string Describe(ApiRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        var direction = request.Direction?.ToLowerInvariant() switch
        {
            "in" => " (incoming)",
            "both" => " (incoming and outgoing)",
            _ => string.Empty,
        };
        var verb = string.Equals(request.Action, "allow", StringComparison.OrdinalIgnoreCase) ? "Allow" : "Block";
        return request.Op switch
        {
            ApiOps.SetRule when request.ExpiresMinutes is int minutes => $"{verb} {Clip(request.App)}{direction} for {minutes} minutes.",
            ApiOps.SetRule => $"{verb} {Clip(request.App)}{direction}.",
            ApiOps.Trust => $"Allow {Clip(request.App)} again as the file is now.",
            ApiOps.RemoveRules => $"Remove the rules for {Clip(request.App)}.",
            ApiOps.RemoveFilter => $"Remove rule number {request.FilterId}.",
            ApiOps.SetMode => $"Switch to the {Clip(request.Mode)} mode" + (request.Apps is { Count: > 0 } apps ? $" and allow {apps.Count} programs." : "."),
            ApiOps.Panic => request.Action?.Trim().ToLowerInvariant() switch
            {
                "allow" => "Pause all rules: every program may connect.",
                "block" => "Block all network traffic.",
                "off" => "Put the rules back in force.",
                "remove" => "Delete every CrioFire rule.",
                _ => "Change the panic setting.",
            },
            ApiOps.AddNetRule => $"{verb} {Clip(request.Protocol ?? "any")} traffic{direction}: ports {Clip(request.Ports ?? "any")}, addresses {Clip(request.Addresses ?? "any")}"
                + (string.IsNullOrWhiteSpace(request.App) ? "." : $", for {Clip(request.App)}."),
            ApiOps.SetServiceRule => $"{verb} the Windows service {Clip(request.Service)}{direction}.",
            ApiOps.RemoveServiceRules => $"Remove the rules for the Windows service {Clip(request.Service)}.",
            ApiOps.SetAutoRule => $"Turn the automatic rule '{Clip(request.AutoRule)}' {(request.Enabled == true ? "on" : "off")}.",
            ApiOps.SetDomainRule => $"{verb} the domain {Clip(request.Domain)}" + (string.IsNullOrWhiteSpace(request.App) ? "." : $" for {Clip(request.App)}."),
            ApiOps.RemoveDomainRule => $"Remove the domain rule {Clip(request.Domain ?? request.DomainRuleId)}.",
            ApiOps.ImportRules => $"Import {request.RuleSet?.Count ?? 0} rules"
                + (string.Equals(request.ImportMode, "replace", StringComparison.OrdinalIgnoreCase) ? ", replacing the rules in force." : "."),
            ApiOps.RestoreBackup => $"Replace the rules in force with the backup {Clip(request.Name)}.",
            ApiOps.SetProtection => request.Enabled == true ? "Turn tamper protection on." : "Turn tamper protection OFF: programs could then change the rules through the CrioFire app.",
            ApiOps.SetLicense => string.IsNullOrWhiteSpace(request.LicenseKey) ? "Remove the license key." : "Enter a license key.",
            ApiOps.SetLogs => "Change how much connection history is kept.",
            ApiOps.ClearLogs => "Delete the connection history.",
            ApiOps.ResetUsage => "Clear the data counts.",
            ApiOps.SetUpdateCheck => request.Enabled == true ? "Turn the daily update check on." : "Turn the daily update check off.",
            ApiOps.StopService => "Stop the CrioFire service.",
            _ => $"Carry out '{Clip(request.Op)}'.",
        };
    }

    /// <summary>Keeps what is shown readable, and to what really is in the request: no line breaks or hidden direction marks.</summary>
    private static string Clip(string? text)
    {
        var clean = new string((text ?? "?").Where(c => !char.IsControl(c) && c is not ('‪' or '‫' or '‬' or '‭' or '‮' or '⁦' or '⁧' or '⁨' or '⁩' or '‎' or '‏')).ToArray());
        return clean.Length > 160 ? clean[..80] + "…" + clean[^70..] : clean;
    }
}

/// <summary>Asks the person at the PC to confirm a change, in a window other programs cannot click (it belongs to an elevated process).</summary>
public static partial class ApprovalPrompt
{
    private const uint YesNo = 0x4;
    private const uint IconWarning = 0x30;
    private const uint DefaultNo = 0x100;
    private const uint SetForeground = 0x10000;
    private const uint TopMost = 0x40000;
    private const int Yes = 6;

    /// <summary>The name the app gives the file for the answer: criofire-approval-, 32 hex digits, .json.</summary>
    public static bool IsAnswerFile(string? path)
    {
        var name = (path ?? string.Empty)[((path ?? string.Empty).LastIndexOfAny(['\\', '/']) + 1)..];
        const string prefix = "criofire-approval-", suffix = ".json";
        return name.Length == prefix.Length + 32 + suffix.Length
            && name.StartsWith(prefix, StringComparison.Ordinal) && name.EndsWith(suffix, StringComparison.Ordinal)
            && name.Skip(prefix.Length).Take(32).All(c => c is (>= '0' and <= '9') or (>= 'a' and <= 'f'));
    }

    /// <summary>
    /// True when the person chose Yes within a minute and a half. "No" is the default button, so a
    /// stray Enter refuses. Windows itself shows the message in the person's session, so it appears
    /// whatever window state this process was started with, and no other program can press its buttons.
    /// </summary>
    public static bool Confirm(string change)
    {
        if (!OperatingSystem.IsWindows())
        {
            return false;
        }

        const string title = "CrioFire Private Firewall";
        var text = "A program asked CrioFire to make this change with administrator rights:\n\n" + change
            + "\n\nIf you did not just ask for this in the CrioFire app, choose No.";
        var session = (uint)System.Diagnostics.Process.GetCurrentProcess().SessionId;
        return WTSSendMessageW(IntPtr.Zero, session, title, (uint)(title.Length * 2), text, (uint)(text.Length * 2),
                   YesNo | IconWarning | DefaultNo | SetForeground | TopMost, 90, out var answer, wait: true)
               && answer == Yes;
    }

    [System.Runtime.InteropServices.LibraryImport("wtsapi32.dll", SetLastError = true, StringMarshalling = System.Runtime.InteropServices.StringMarshalling.Utf16)]
    [return: System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.Bool)]
    private static partial bool WTSSendMessageW(IntPtr server, uint sessionId, string title, uint titleBytes, string message, uint messageBytes,
        uint style, uint timeoutSeconds, out int response, [System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.Bool)] bool wait);
}
