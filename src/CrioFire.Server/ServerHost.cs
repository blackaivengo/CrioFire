using System.Threading.RateLimiting;
using CrioFire.Core.Management;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection;

namespace CrioFire.Server;

/// <summary>The HTTPS server PCs talk to.</summary>
internal static class ServerHost
{
    public const string SignInLimit = "signin";

    private const long MaxRequestBytes = 1024 * 1024;

    public static async Task RunAsync(string[] args, string folder, ServerSettings settings)
    {
        var certificate = ServerCertificate.LoadOrCreate(folder, DateTime.UtcNow);
        var store = new ServerStore(folder);

        var admins = new AdminAccounts(folder);
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            Args = args.Length > 0 && args[0] == "run" ? args[1..] : args,
            ContentRootPath = AppContext.BaseDirectory,   // the console's files (wwwroot) sit next to the program
        });
        builder.Host.UseWindowsService(o => o.ServiceName = "criofire-server");
        builder.WebHost.ConfigureKestrel(k =>
        {
            k.Limits.MaxRequestBodySize = MaxRequestBytes;
            k.AddServerHeader = false;
            k.ListenAnyIP(settings.Port, listen => listen.UseHttps(certificate));
        });
        builder.Logging.AddFilter("Microsoft.AspNetCore", LogLevel.Warning);   // not a line per check-in
        builder.Services.AddSingleton(store);
        builder.Services.AddHostedService<StoreSaver>();

        // The admin console: cookie sign-in, keys kept in the data folder (encrypted for this machine on Windows).
        var keys = builder.Services.AddDataProtection().SetApplicationName("CrioFire Server")
            .PersistKeysToFileSystem(new DirectoryInfo(Path.Combine(folder, "keys")));
        if (OperatingSystem.IsWindows())
        {
            keys.ProtectKeysWithDpapi(protectToLocalMachine: true);
        }

        builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme).AddCookie(o =>
        {
            o.Cookie.Name = "criofire-admin";
            o.Cookie.HttpOnly = true;
            o.Cookie.SecurePolicy = CookieSecurePolicy.Always;
            o.Cookie.SameSite = SameSiteMode.Strict;
            o.ExpireTimeSpan = TimeSpan.FromHours(8);
            o.SlidingExpiration = true;
            o.Events.OnRedirectToLogin = c =>
            {
                c.Response.StatusCode = StatusCodes.Status401Unauthorized;
                return Task.CompletedTask;
            };
            o.Events.OnRedirectToAccessDenied = c =>
            {
                c.Response.StatusCode = StatusCodes.Status403Forbidden;
                return Task.CompletedTask;
            };
        });
        builder.Services.AddAuthorization();
        builder.Services.AddRateLimiter(o =>
        {
            o.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
            o.AddPolicy(SignInLimit, context => RateLimitPartition.GetFixedWindowLimiter(
                context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
                _ => new FixedWindowRateLimiterOptions { PermitLimit = 10, Window = TimeSpan.FromMinutes(1) }));
        });

        var app = builder.Build();
        app.Use(async (context, next) =>
        {
            var headers = context.Response.Headers;
            headers["X-Content-Type-Options"] = "nosniff";
            headers["X-Frame-Options"] = "DENY";
            headers["Referrer-Policy"] = "no-referrer";
            headers["Content-Security-Policy"] = "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; frame-ancestors 'none'";
            await next(context).ConfigureAwait(false);
        });
        app.UseDefaultFiles();
        app.UseStaticFiles();
        app.UseRateLimiter();
        app.UseAuthentication();
        app.UseAuthorization();

        var hostNames = ServerCertificate.HostNames();
        MapAgentApi(app, store, Environment.MachineName, settings.CheckinSeconds);
        AdminApi.Map(app, store, admins, settings, Environment.MachineName, hostNames[^2], Fingerprints.Of(certificate));
        await app.RunAsync().ConfigureAwait(false);
    }

    /// <summary>The endpoints PCs use: enroll once, check in every few minutes, and send connections when asked.</summary>
    public static void MapAgentApi(IEndpointRouteBuilder app, ServerStore store, string serverName, int checkinSeconds)
    {
        app.MapGet("/health", () => Results.Text("ok"));

        app.MapPost("/api/v1/enroll", async (HttpContext context) =>
        {
            var request = await context.Request.ReadFromJsonAsync(ManagementJson.Default.EnrollRequest).ConfigureAwait(false);
            if (request is null)
            {
                return Results.BadRequest("Malformed request.");
            }

            var response = store.Enroll(request, serverName, Address(context), DateTime.UtcNow, out var error);
            return response is null
                ? Results.Json(error, statusCode: StatusCodes.Status403Forbidden)
                : Results.Json(response, ManagementJson.Default.EnrollResponse);
        });

        app.MapPost("/api/v1/checkin", async (HttpContext context) =>
        {
            var device = store.Authenticate(context.Request.Headers.Authorization.ToString());
            if (device is null)
            {
                return Results.Json("This PC is not enrolled with this server (or it was removed). Enroll it again.", statusCode: StatusCodes.Status401Unauthorized);
            }

            var report = await context.Request.ReadFromJsonAsync(ManagementJson.Default.CheckinReport).ConfigureAwait(false);
            if (report is null)
            {
                return Results.BadRequest("Malformed request.");
            }

            store.RecordCheckin(device.DeviceId, report, Address(context), DateTime.UtcNow);
            var pending = store.PendingActivity(device.DeviceId);

            // The whole policy goes only when the PC has another one (or another version); otherwise
            // the answer stays a few bytes.
            var policy = store.AssignedPolicy(device.DeviceId);
            var send = policy is not null && (report.PolicyId != policy.Id || report.PolicyVersion != policy.Version);
            return Results.Json(
                new CheckinResponse(policy?.Version ?? 0, DateTime.UtcNow, checkinSeconds, pending, policy?.Id, send ? policy!.ToManaged() : null),
                ManagementJson.Default.CheckinResponse);
        });

        app.MapPost("/api/v1/activity", async (HttpContext context) =>
        {
            var device = store.Authenticate(context.Request.Headers.Authorization.ToString());
            if (device is null)
            {
                return Results.Json("This PC is not enrolled with this server.", statusCode: StatusCodes.Status401Unauthorized);
            }

            var upload = await context.Request.ReadFromJsonAsync(ManagementJson.Default.ActivityUpload).ConfigureAwait(false);
            return upload is null ? Results.BadRequest("Malformed request.")
                : store.StoreActivity(device.DeviceId, upload, DateTime.UtcNow) ? Results.NoContent()
                : Results.Json("Nobody asked for this.", statusCode: StatusCodes.Status409Conflict);
        });
    }

    private static string? Address(HttpContext context) =>
        context.Connection.RemoteIpAddress is { } ip ? (ip.IsIPv4MappedToIPv6 ? ip.MapToIPv4() : ip).ToString() : null;
}

/// <summary>Writes check-ins to disk every few seconds instead of on every request.</summary>
internal sealed class StoreSaver(ServerStore store) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(10));
        try
        {
            while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false))
            {
                store.SaveIfChanged();
            }
        }
        catch (OperationCanceledException)
        {
        }
        finally
        {
            store.SaveIfChanged();
        }
    }
}
