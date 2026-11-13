using CrioFire.Core;
using CrioFire.Core.Api;

namespace CrioFire.Service;

/// <summary>
/// Hosts the local API (\\.\pipe\criofire) so criofire-ui.exe and criofire.exe can work without
/// administrator rights. Uses its own filtering-engine session.
/// </summary>
internal sealed partial class ApiService(ILogger<ApiService> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            using var engine = WfpEngine.Open();
            var server = new ApiServer(new ApiHandler(
                engine,
                new TemporaryRuleStore(TemporaryRuleStore.DefaultPath),
                new TrafficLog(TrafficLog.DefaultPath),
                new TrafficLog(TrafficLog.AllowedPath),
                new IdentityGuard(new ProgramIdentityStore(ProgramIdentityStore.DefaultPath), new AuthenticodeSignatures()),
                new RuleBackupStore(RuleBackupStore.DefaultFolder)));
            LogListening(logger, ApiServer.DefaultPipeName);
            await server.RunAsync(stoppingToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            // Service stopping.
        }
        catch (Exception ex) when (ex is WfpException or IOException or UnauthorizedAccessException)
        {
            // UnauthorizedAccessException here usually means another process already owns the pipe name.
            LogFailed(logger, ex);
        }
    }

    [LoggerMessage(Level = LogLevel.Information, Message = "Local API listening on named pipe {PipeName}.")]
    private static partial void LogListening(ILogger logger, string pipeName);

    [LoggerMessage(Level = LogLevel.Error, Message = "The local API could not start.")]
    private static partial void LogFailed(ILogger logger, Exception exception);
}
