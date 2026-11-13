using System.Security.Claims;
using CrioFire.Core;
using CrioFire.Core.Management;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;

namespace CrioFire.Server;

/// <summary>A PC as the console shows it.</summary>
/// <param name="Status">ok, attention, offline or new (never checked in).</param>
/// <param name="Problems">Plain-language reasons for "attention" or "offline".</param>
/// <param name="PolicyApplied">The PC runs the current version of its policy.</param>
public sealed record DeviceView(
    string Id,
    string Computer,
    string? Address,
    DateTime EnrolledUtc,
    DateTime? LastSeenUtc,
    string Status,
    List<string> Problems,
    CheckinReport? Report,
    string? PolicyId,
    string? PolicyName,
    bool PolicyApplied,
    bool ActivityRequested,
    DateTime? ActivityUploadedUtc);

public sealed record PolicyView(ServerPolicy Policy, int Computers, bool IsDefault);

public sealed record Overview(string Server, int Computers, int Online, int Attention, int Offline, int Policies, int Unmanaged, List<DeviceView> NeedAttention);

public sealed record SignIn(string Name, string Password);

public sealed record PolicyInput(string Name, string? Mode, bool AllowUserRules, bool RequireAdmin, RuleSet Rules);

public sealed record AssignInput(List<string> DeviceIds, string? PolicyId);

public sealed record DevicesInput(List<string> DeviceIds);

public sealed record ActivityInput(string Kind, int Hours, int Limit);

public sealed record TokenInput(int Uses, int Days, string? Note);

/// <summary>An enrollment code as the console shows it: without its hash.</summary>
public sealed record TokenView(string Id, DateTime CreatedUtc, DateTime ExpiresUtc, int UsesLeft, string? Note)
{
    public static TokenView Of(EnrollmentToken t) => new(t.Id, t.CreatedUtc, t.ExpiresUtc, t.UsesLeft, t.Note);
}

public sealed record NewAdmin(string Name, string Password);

public sealed record PasswordChange(string Current, string New);

/// <summary>
/// The admin console's API (/api/admin/...), used by the web console in wwwroot. Every call but
/// sign-in needs a signed-in administrator; every change also needs the X-CrioFire header, which
/// other sites cannot send (with the SameSite=Strict cookie, this stops cross-site requests).
/// </summary>
internal static class AdminApi
{
    public const string CsrfHeader = "X-CrioFire";

    public static void Map(WebApplication app, ServerStore store, AdminAccounts admins, ServerSettings settings, string serverName, string enrollHost, string fingerprint)
    {
        var api = app.MapGroup("/api/admin").AddEndpointFilter(async (context, next) =>
        {
            var http = context.HttpContext;
            if (!HttpMethods.IsGet(http.Request.Method) && http.Request.Headers[CsrfHeader] != "1")
            {
                return Results.Json(new { error = "Missing the console's request header." }, statusCode: StatusCodes.Status400BadRequest);
            }

            try
            {
                return await next(context).ConfigureAwait(false);
            }
            catch (ArgumentException ex)
            {
                return Results.Json(new { error = ex.Message }, statusCode: StatusCodes.Status400BadRequest);
            }
        });

        // Not signed in yet.
        api.MapGet("/state", () => Results.Json(new { server = serverName, adminsExist = admins.Any() }));
        api.MapPost("/signin", async (HttpContext http, SignIn input) =>
        {
            var account = admins.Verify(input.Name, input.Password, DateTime.UtcNow);
            if (account is null)
            {
                await Task.Delay(Random.Shared.Next(200, 600)).ConfigureAwait(false);
                return Results.Json(new { error = "Wrong name or password." }, statusCode: StatusCodes.Status401Unauthorized);
            }

            var identity = new ClaimsIdentity([new Claim(ClaimTypes.Name, account.Name)], CookieAuthenticationDefaults.AuthenticationScheme);
            await http.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(identity)).ConfigureAwait(false);
            return Results.Json(new { name = account.Name });
        }).RequireRateLimiting(ServerHost.SignInLimit);

        var signedIn = api.MapGroup(string.Empty).RequireAuthorization();
        signedIn.MapPost("/signout", async (HttpContext http) =>
        {
            await http.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme).ConfigureAwait(false);
            return Results.NoContent();
        });
        signedIn.MapGet("/me", (ClaimsPrincipal user) => Results.Json(new { name = user.Identity?.Name }));

        signedIn.MapGet("/overview", () =>
        {
            var devices = Devices(store, settings);
            return Results.Json(new Overview(
                serverName,
                devices.Count,
                devices.Count(d => d.Status is "ok" or "attention"),
                devices.Count(d => d.Status == "attention"),
                devices.Count(d => d.Status is "offline" or "new"),
                store.Policies().Count,
                devices.Count(d => d.PolicyId is null),
                devices.Where(d => d.Status is "attention" or "offline").Take(20).ToList()));
        });

        signedIn.MapGet("/devices", () => Results.Json(Devices(store, settings)));
        signedIn.MapPost("/devices/assign", (AssignInput input) =>
        {
            foreach (var id in input.DeviceIds)
            {
                store.Assign(id, string.IsNullOrEmpty(input.PolicyId) ? null : input.PolicyId);
            }

            return Results.Json(new { count = input.DeviceIds.Count });
        });
        signedIn.MapPost("/devices/remove", (DevicesInput input) =>
            Results.Json(new { count = input.DeviceIds.Count(store.RemoveDevice) }));
        signedIn.MapPost("/devices/{id}/activity", (string id, ActivityInput input) =>
            Results.Json(store.RequestActivity(id, input.Kind, input.Hours, input.Limit, DateTime.UtcNow)));
        signedIn.MapGet("/devices/{id}/activity", (string id) =>
            Results.Json(new { pending = store.PendingActivity(id), upload = store.Activity(id) }));

        signedIn.MapGet("/policies", () =>
        {
            var counts = store.Devices().GroupBy(d => store.AssignedPolicy(d.DeviceId)?.Id ?? string.Empty).ToDictionary(g => g.Key, g => g.Count());
            var fallback = store.DefaultPolicyId();
            return Results.Json(store.Policies().Select(p => new PolicyView(p, counts.GetValueOrDefault(p.Id), p.Id == fallback)).ToList());
        });
        signedIn.MapPost("/policies", (PolicyInput input) =>
            Results.Json(store.CreatePolicy(input.Name, input.Rules, Mode(input.Mode), input.AllowUserRules, input.RequireAdmin, DateTime.UtcNow)));
        signedIn.MapPut("/policies/{id}", (string id, PolicyInput input) =>
            Results.Json(store.UpdatePolicy(id, p => p with
            {
                Name = input.Name,
                Mode = Mode(input.Mode),
                AllowUserRules = input.AllowUserRules,
                RequireAdmin = input.RequireAdmin,
                Rules = input.Rules,
            }, DateTime.UtcNow)));
        signedIn.MapDelete("/policies/{id}", (string id) =>
            store.DeletePolicy(id) ? Results.NoContent() : Results.NotFound());
        signedIn.MapPost("/policies/{id}/default", (string id) =>
        {
            store.SetDefaultPolicy(id == "none" ? null : id);
            return Results.NoContent();
        });

        // Codes that can still enroll a PC. Their hashes stay on the server.
        signedIn.MapGet("/tokens", () => Results.Json(store.Tokens()
            .Where(t => t.ExpiresUtc > DateTime.UtcNow && t.UsesLeft > 0)
            .Select(TokenView.Of)
            .ToList()));
        signedIn.MapPost("/tokens", (TokenInput input) =>
        {
            if (input.Uses is < 1 or > 100_000 || input.Days is < 1 or > 365)
            {
                throw new ArgumentException("Uses must be 1 to 100000 and days 1 to 365.");
            }

            var (token, record) = store.CreateToken(TimeSpan.FromDays(input.Days), input.Uses, input.Note, DateTime.UtcNow);
            return Results.Json(new
            {
                token,
                record = TokenView.Of(record),
                command = $"criofire enroll {enrollHost}:{settings.Port} {token} --fingerprint {fingerprint}",
            });
        });
        signedIn.MapDelete("/tokens/{id}", (string id) => store.RevokeToken(id) ? Results.NoContent() : Results.NotFound());

        signedIn.MapGet("/admins", () => Results.Json(admins.List().Select(a => new { a.Name, a.CreatedUtc, a.LastSignInUtc })));
        signedIn.MapPost("/admins", (NewAdmin input) =>
        {
            admins.Add(input.Name, input.Password, DateTime.UtcNow);
            return Results.NoContent();
        });
        signedIn.MapDelete("/admins/{name}", (string name, ClaimsPrincipal user) =>
        {
            if (string.Equals(name, user.Identity?.Name, StringComparison.OrdinalIgnoreCase))
            {
                throw new ArgumentException("You cannot remove yourself. Ask another administrator.");
            }

            admins.Remove(name);
            return Results.NoContent();
        });
        signedIn.MapPost("/password", (PasswordChange input, ClaimsPrincipal user) =>
        {
            var name = user.Identity?.Name ?? string.Empty;
            if (admins.Verify(name, input.Current, DateTime.UtcNow) is null)
            {
                throw new ArgumentException("The current password is not right.");
            }

            admins.SetPassword(name, input.New);
            return Results.NoContent();
        });
    }

    /// <summary>Every PC with its state judged: online, needing attention (and why), or offline.</summary>
    public static List<DeviceView> Devices(ServerStore store, ServerSettings settings) => Devices(store, settings, DateTime.UtcNow);

    internal static List<DeviceView> Devices(ServerStore store, ServerSettings settings, DateTime now)
    {
        var offlineAfter = TimeSpan.FromSeconds(Math.Max(settings.CheckinSeconds * 3, 180));
        return store.Devices().Select(d =>
        {
            var policy = store.AssignedPolicy(d.DeviceId);
            var r = d.LastReport;
            var applied = policy is null ? r?.PolicyId is null : r?.PolicyId == policy.Id && r.PolicyVersion == policy.Version;
            var problems = new List<string>();
            string status;
            if (d.LastSeenUtc is null || r is null)
            {
                status = "new";
                problems.Add("Has not checked in yet.");
            }
            else if (now - d.LastSeenUtc > offlineAfter)
            {
                status = "offline";
                problems.Add($"Last check-in {Ago(now - d.LastSeenUtc.Value)} ago.");
            }
            else
            {
                if (!r.Installed)
                {
                    problems.Add("CrioFire is not set up on this PC.");
                }

                if (r.Panic != "off")
                {
                    problems.Add(r.Panic == "block" ? "Panic: all network traffic blocked." : "Panic: everything allowed, rules paused.");
                }

                if (r.ChangedPrograms > 0)
                {
                    problems.Add($"{r.ChangedPrograms} allowed program(s) changed since they were allowed.");
                }

                if (!applied)
                {
                    problems.Add(policy is null ? "Still removing an old policy." : "Has not applied its policy yet.");
                }

                if (r.License is LicenseStates.Expired or LicenseStates.Invalid)
                {
                    problems.Add($"License {r.License}.");
                }

                status = problems.Count == 0 ? "ok" : "attention";
            }

            return new DeviceView(d.DeviceId, d.Computer, d.Address, d.EnrolledUtc, d.LastSeenUtc, status, problems, r,
                policy?.Id, policy?.Name, applied, store.PendingActivity(d.DeviceId) is not null, d.ActivityUploadedUtc);
        }).ToList();
    }

    private static string? Mode(string? mode) => string.IsNullOrWhiteSpace(mode) || mode == "any" ? null : mode;

    private static string Ago(TimeSpan span) =>
        span.TotalDays >= 2 ? $"{(int)span.TotalDays} days" : span.TotalHours >= 2 ? $"{(int)span.TotalHours} hours" : $"{Math.Max(1, (int)span.TotalMinutes)} minutes";
}
