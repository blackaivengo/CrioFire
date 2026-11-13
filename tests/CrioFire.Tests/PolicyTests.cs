using CrioFire.Core;
using CrioFire.Core.Api;
using CrioFire.Core.Management;
using CrioFire.Server;

namespace CrioFire.Tests;

public sealed class PolicyTests : IDisposable
{
    private static readonly DateTime Now = new(2026, 11, 13, 3, 0, 0, DateTimeKind.Utc);
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "criofire-policy-" + Guid.NewGuid().ToString("N"));

    public void Dispose()
    {
        if (Directory.Exists(_dir))
        {
            Directory.Delete(_dir, recursive: true);
        }
    }

    [Fact]
    public void EditingAPolicyRaisesItsVersion()
    {
        var store = new ServerStore(_dir);
        var policy = store.CreatePolicy("Office", Rules(), "ask", allowUserRules: true, requireAdmin: false, Now);

        var changed = store.UpdatePolicy(policy.Id, p => p with { AllowUserRules = false, Mode = null }, Now.AddMinutes(1));

        Assert.Equal(1, policy.Version);
        Assert.Equal(2, changed.Version);
        Assert.False(changed.AllowUserRules);
        Assert.Null(changed.Mode);
        Assert.Equal(2, store.Policy(policy.Id)!.Version);   // read back from disk
        Assert.Single(store.Policies());
    }

    [Fact]
    public void BadPoliciesAreRefused()
    {
        var store = new ServerStore(_dir);
        Assert.Throws<ArgumentException>(() => store.CreatePolicy(" ", Rules(), null, true, false, Now));
        Assert.Throws<ArgumentException>(() => store.CreatePolicy("x", Rules(), "chaos", true, false, Now));
        Assert.Throws<ArgumentException>(() => store.CreatePolicy("x", new RuleSet { Programs = [new(@"C:\a.exe", "maybe", "out")] }, null, true, false, Now));
        Assert.Throws<ArgumentException>(() => store.UpdatePolicy("pol_missing", p => p, Now));
    }

    [Fact]
    public void PcsGetTheDefaultPolicyWhenTheyEnrollAndCanBeMoved()
    {
        var store = new ServerStore(_dir);
        var office = store.CreatePolicy("Office", Rules(), null, true, false, Now);
        var kiosk = store.CreatePolicy("Kiosk", Rules(), "allowlist", false, true, Now);
        store.SetDefaultPolicy(office.Id);
        var (token, _) = store.CreateToken(TimeSpan.FromDays(1), 2, null, Now);

        var pc = store.Enroll(new EnrollRequest(token, "PC-1", null, null), "s", null, Now, out _)!;
        Assert.Equal(office.Id, store.AssignedPolicy(pc.DeviceId)!.Id);

        store.Assign(pc.DeviceId, kiosk.Id);
        Assert.Equal(kiosk.Id, store.AssignedPolicy(pc.DeviceId)!.Id);

        store.Assign(pc.DeviceId, null);
        Assert.Null(store.AssignedPolicy(pc.DeviceId));
        Assert.Throws<ArgumentException>(() => store.Assign(pc.DeviceId, "pol_missing"));
    }

    [Fact]
    public void DeletingAPolicyLeavesItsPcsWithoutOne()
    {
        var store = new ServerStore(_dir);
        var policy = store.CreatePolicy("Office", Rules(), null, true, false, Now);
        store.SetDefaultPolicy(policy.Id);
        var (token, _) = store.CreateToken(TimeSpan.FromDays(1), 1, null, Now);
        var pc = store.Enroll(new EnrollRequest(token, "PC-1", null, null), "s", null, Now, out _)!;

        Assert.True(store.DeletePolicy(policy.Id));

        Assert.Null(store.AssignedPolicy(pc.DeviceId));
        Assert.Null(store.DefaultPolicyId());
        Assert.False(store.DeletePolicy(policy.Id));
    }

    [Fact]
    public void TheServerSendsWhatThePcNeedsToApply()
    {
        var store = new ServerStore(_dir);
        var policy = store.CreatePolicy("Office", Rules(), "ask", false, true, Now);

        var managed = policy.ToManaged();

        Assert.Equal(policy.Id, managed.Id);
        Assert.Equal(policy.Version, managed.Version);
        Assert.Equal("ask", managed.Mode);
        Assert.False(managed.AllowUserRules);
        Assert.True(managed.RequireAdmin);
        Assert.Equal(2, managed.Rules.Count);
    }

    [Fact]
    public void ALockedPolicyStopsUsersChangingRulesModeAndProtection()
    {
        var store = new ManagedPolicyStore(Path.Combine(_dir, "policy.json"));
        Directory.CreateDirectory(_dir);
        store.Save(new ManagedPolicy("pol_1", 3, "Kiosk", "allowlist", AllowUserRules: false, RequireAdmin: true, Rules(), Now));
        var handler = new ApiHandler(null!, policy: store);

        foreach (var op in new[] { ApiOps.SetRule, ApiOps.RemoveRules, ApiOps.AddNetRule, ApiOps.SetServiceRule, ApiOps.ImportRules, ApiOps.Trust })
        {
            var refused = handler.Handle(new ApiRequest { Op = op, App = @"C:\a.exe", Action = "allow" }, ClientRights.Administrator);
            Assert.False(refused.Ok);
            Assert.Equal(ManagedPolicies.LockedMessage, refused.Error);
        }

        Assert.Contains("organization", handler.Handle(new ApiRequest { Op = ApiOps.SetMode, Mode = "learning" }, ClientRights.Administrator).Error, StringComparison.Ordinal);
        Assert.Contains("organization", handler.Handle(new ApiRequest { Op = ApiOps.SetProtection, Enabled = false }, ClientRights.Administrator).Error, StringComparison.Ordinal);
        Assert.Equal("Kiosk", store.Load()!.Name);
    }

    [Fact]
    public void UserExportsLeaveOrganizationRulesOut()
    {
        var mine = new CrioFireFilter(1, "a", FilterLayers.ConnectV4, new RuleDescription(RuleAction.Allow, TrafficDirection.Outbound, @"C:\mine.exe"));
        var theirs = new CrioFireFilter(2, "b", FilterLayers.ConnectV4, new RuleDescription(RuleAction.Block, TrafficDirection.Outbound, @"C:\theirs.exe"), Managed: true);

        var set = RuleBackup.FromFilters([mine, theirs], [], null, "PC", Now);

        Assert.Equal(@"C:\mine.exe", Assert.Single(set.Programs).App);
        Assert.True(RuleInfo.From(theirs).Managed);
    }

    private static RuleSet Rules() => new()
    {
        Programs = [new("System", "allow", "in")],
        Network = [new("block", "in", "tcp", "445", "", null)],
    };
}
