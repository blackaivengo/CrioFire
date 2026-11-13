using System.Text.Json;

namespace CrioFire.Core;

/// <summary>
/// A policy from the organization's CrioFire Server: rules that apply on top of the user's own
/// (organization rules always win), and what the user may still change.
/// </summary>
/// <param name="Id">The policy on the server (pol_...).</param>
/// <param name="Version">Changes whenever the policy is edited.</param>
/// <param name="Mode">The mode the organization sets (learning, ask, allowlist), or null to leave it to the user.</param>
/// <param name="AllowUserRules">False: the user's own rules are removed (a backup is kept) and the user cannot add any.</param>
/// <param name="RequireAdmin">True: tamper protection is switched on and cannot be switched off on this PC.</param>
/// <param name="Rules">The organization's rules (and automatic-rule settings).</param>
public sealed record ManagedPolicy(
    string Id,
    int Version,
    string Name,
    string? Mode,
    bool AllowUserRules,
    bool RequireAdmin,
    RuleSet Rules,
    DateTime UpdatedUtc);

/// <summary>The policy in force on this PC: %ProgramData%\criofire\policy.json.</summary>
public sealed class ManagedPolicyStore(string path)
{
    private static readonly Lock Gate = new();

    public static string DefaultPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "criofire", "policy.json");

    public string FilePath { get; } = path;

    public ManagedPolicy? Load()
    {
        lock (Gate)
        {
            try
            {
                return File.Exists(FilePath) ? JsonSerializer.Deserialize(File.ReadAllText(FilePath), Management.ManagementJson.Default.ManagedPolicy) : null;
            }
            catch (JsonException)
            {
                return null;
            }
        }
    }

    public void Save(ManagedPolicy policy)
    {
        ArgumentNullException.ThrowIfNull(policy);
        lock (Gate)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(FilePath))!);
            File.WriteAllText(FilePath + ".tmp", JsonSerializer.Serialize(policy, Management.ManagementJson.Default.ManagedPolicy));
            File.Move(FilePath + ".tmp", FilePath, overwrite: true);
        }
    }

    public void Delete()
    {
        lock (Gate)
        {
            if (File.Exists(FilePath))
            {
                File.Delete(FilePath);
            }
        }
    }
}

/// <summary>Applies and removes organization policies.</summary>
public static class ManagedPolicies
{
    public const string LockedMessage = "Rules on this PC are managed by your organization.";

    /// <summary>
    /// Puts a policy in force: the organization's rules replace the previous ones (in their own
    /// sublayer, above the user's), and the policy's mode, automatic rules, tamper protection and
    /// "no user rules" are applied. Rules for programs that are not on this PC are skipped.
    /// Returns how many organization rules were written.
    /// </summary>
    public static int Apply(
        WfpEngine engine,
        ManagedPolicy policy,
        RuleBackupStore? backups,
        TemporaryRuleStore? temporaryRules,
        TamperProtection? protection,
        DateTime nowUtc)
    {
        ArgumentNullException.ThrowIfNull(engine);
        ArgumentNullException.ThrowIfNull(policy);
        if (RuleBackup.Validate(policy.Rules) is { } invalid)
        {
            throw new ArgumentException($"The organization's policy is not valid: {invalid}");
        }

        if (!engine.IsInstalled())
        {
            engine.Install();
        }

        engine.ClearManaged();
        var written = engine.Managed(() =>
        {
            var count = 0;
            foreach (var p in policy.Rules.Programs)
            {
                if (KnownApps.IsKernel(p.App) || StoreApps.IsPackage(p.App) || File.Exists(p.App))
                {
                    engine.SetAppRule(p.App, Action(p.Action), Direction(p.Direction));
                    count++;
                }
            }

            foreach (var n in policy.Rules.Network)
            {
                if (RuleBackup.ToNetRule(n, out _) is { } rule && (rule.AppPath is null || File.Exists(rule.AppPath)))
                {
                    engine.AddNetRule(rule);
                    count++;
                }
            }

            foreach (var s in policy.Rules.Services)
            {
                engine.SetServiceRule(s.Service, Action(s.Action), Direction(s.Direction));
                count++;
            }

            return count;
        });

        if (!policy.AllowUserRules)
        {
            // The organization decides alone: the user's own rules go, after a backup.
            var own = RuleBackup.Export(engine, temporaryRules, nowUtc);
            if (own.Count > 0)
            {
                backups?.Save(own, "before-policy");
                RuleBackup.Apply(engine, new RuleSet { AutoRules = own.AutoRules, Mode = own.Mode }, ImportMode.Replace, temporaryRules, applyMode: false, nowUtc);
            }

            temporaryRules?.Clear();
        }

        var current = engine.GetAutoRules();
        foreach (var auto in policy.Rules.AutoRules.Where(a => AutoRulePolicy.IsKnown(a.Name)))
        {
            if (current.FirstOrDefault(c => string.Equals(c.Name, auto.Name, StringComparison.OrdinalIgnoreCase)).Enabled != auto.Enabled)
            {
                engine.SetAutoRule(auto.Name, auto.Enabled);
            }
        }

        if (policy.Mode is { } text && FilterDescriptions.TryParseMode(text, out var mode) && engine.GetMode() != mode)
        {
            engine.SetMode(mode);
        }

        if (policy.RequireAdmin)
        {
            protection?.SetRequireAdmin(true);
        }

        return written;
    }

    /// <summary>The PC left the organization's management: its rules go, the user's stay.</summary>
    public static int Clear(WfpEngine engine, ManagedPolicyStore store)
    {
        ArgumentNullException.ThrowIfNull(engine);
        ArgumentNullException.ThrowIfNull(store);
        store.Delete();
        return engine.IsInstalled() ? engine.ClearManaged() : 0;
    }

    private static RuleAction Action(string text) =>
        text.Equals("allow", StringComparison.OrdinalIgnoreCase) ? RuleAction.Allow : RuleAction.Block;

    private static TrafficDirection Direction(string text) => text.ToLowerInvariant() switch
    {
        "in" => TrafficDirection.Inbound,
        "both" => TrafficDirection.Both,
        _ => TrafficDirection.Outbound,
    };
}
