using System.ComponentModel;
using CrioFire.Core;
using CrioFire.Core.Api;

namespace CrioFire.Service;

/// <summary>
/// The service guarding itself:
/// - its process is closed to other programs' attempts to end it or write into it;
/// - with tamper protection on, stopping, pausing, reconfiguring or deleting the service is left
///   to SYSTEM (Windows Installer, and this service when an elevated CrioFire asks), the lock is
///   put back every minute, and so is "start with Windows" if something disabled it;
/// - it notes when the previous run ended without a clean stop;
/// - it checks CrioFire's own files against the build's list, shortly after start and every 6 hours.
/// The rules themselves do not depend on any of this: they live in the Windows Filtering
/// Platform and stay in force while the service is not running.
/// </summary>
internal sealed partial class ProtectionService(ILogger<ProtectionService> logger, SelfProtection self, IHostApplicationLifetime lifetime) : BackgroundService
{
    private static readonly TimeSpan Tick = TimeSpan.FromMinutes(1);
    private static readonly TimeSpan FirstFileCheck = TimeSpan.FromSeconds(20);
    private static readonly TimeSpan FileCheckEvery = TimeSpan.FromHours(6);

    private readonly Lock _lockGate = new();
    private bool? _locked;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var settings = new TamperProtection(TamperProtection.DefaultPath);
        // A moment later, so the client that asked still gets its answer.
        self.StopRequested = () => _ = Task.Run(async () =>
        {
            await Task.Delay(TimeSpan.FromMilliseconds(500)).ConfigureAwait(false);
            lifetime.StopApplication();
        });
        self.ProtectionChanged = ApplyLock;

        try
        {
            ServiceGuard.HardenProcess();
        }
        catch (Exception ex) when (ex is Win32Exception or EntryPointNotFoundException)
        {
            LogStepFailed(logger, "Protecting the service process", ex);
        }

        if (self.NoteStart(DateTime.UtcNow) is { } lastAlive)
        {
            LogUnexpectedStop(logger, lastAlive.ToLocalTime());
        }

        var nextFileCheck = DateTime.UtcNow + FirstFileCheck;
        try
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                var locked = settings.RequireAdmin;
                ApplyLock(locked);
                if (locked)
                {
                    try
                    {
                        if (ServiceGuard.EnsureAutomaticStart())
                        {
                            LogStartRepaired(logger);
                        }
                    }
                    catch (Exception ex) when (ex is Win32Exception or UnauthorizedAccessException or System.Security.SecurityException)
                    {
                        LogStepFailed(logger, "Checking that the service starts with Windows", ex);
                    }
                }

                var wait = Tick;
                if (DateTime.UtcNow >= nextFileCheck)
                {
                    CheckFiles();
                    nextFileCheck = DateTime.UtcNow + FileCheckEvery;
                }
                else if (nextFileCheck - DateTime.UtcNow < wait)
                {
                    wait = nextFileCheck - DateTime.UtcNow;
                }

                self.Heartbeat(DateTime.UtcNow);
                await Task.Delay(wait, stoppingToken).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException)
        {
            // Service stopping.
        }
        finally
        {
            // Asked to stop (Windows shutting down, an upgrade, an administrator through CrioFire): not tampering.
            self.NoteCleanStop();
        }
    }

    /// <summary>Locks or unlocks the service's permissions: on every pass while locked (to undo changes), otherwise when the setting changes.</summary>
    private void ApplyLock(bool locked)
    {
        lock (_lockGate)
        {
            if (!locked && _locked == false)
            {
                return;
            }

            try
            {
                ServiceGuard.SetServiceLock(locked);
                if (_locked != locked)
                {
                    LogLock(logger, locked ? "locked: only SYSTEM may stop or change it" : "unlocked: administrators may stop or change it");
                }

                _locked = locked;
            }
            catch (Exception ex) when (ex is Win32Exception or EntryPointNotFoundException)
            {
                // Not running as a service (a developer's console), or the service has another name.
                LogStepFailed(logger, "Setting the service's permissions", ex);
            }
        }
    }

    private void CheckFiles()
    {
        try
        {
            var before = self.Latest?.Findings.Count ?? 0;
            var result = self.Check(DateTime.UtcNow);
            if (result.State == IntegrityStates.Unchecked)
            {
                LogNoManifest(logger, IntegrityManifest.FileName);
            }
            else if (result.Findings.Count > 0 && result.Findings.Count != before)
            {
                LogFilesChanged(logger, result.Findings.Count, string.Join(", ", result.Findings.Take(10).Select(f => $"{f.Path} ({f.Kind})")));
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            LogStepFailed(logger, "Checking CrioFire's files", ex);
        }
    }

    [LoggerMessage(Level = LogLevel.Warning, Message = "The CrioFire service ended without being stopped (killed, crashed, or the PC lost power); it was last running at {LastAlive}. The rules stayed in force.")]
    private static partial void LogUnexpectedStop(ILogger logger, DateTime lastAlive);

    [LoggerMessage(Level = LogLevel.Warning, Message = "{Count} of CrioFire's own files are not the installed ones: {Files}. Repair or reinstall CrioFire.")]
    private static partial void LogFilesChanged(ILogger logger, int count, string files);

    [LoggerMessage(Level = LogLevel.Information, Message = "No {Manifest} in the install folder (a build from source): CrioFire's files are not checked.")]
    private static partial void LogNoManifest(ILogger logger, string manifest);

    [LoggerMessage(Level = LogLevel.Warning, Message = "The criofire service had been set not to start with Windows; it starts automatically again.")]
    private static partial void LogStartRepaired(ILogger logger);

    [LoggerMessage(Level = LogLevel.Information, Message = "The criofire service is {State}.")]
    private static partial void LogLock(ILogger logger, string state);

    [LoggerMessage(Level = LogLevel.Warning, Message = "{Step} failed.")]
    private static partial void LogStepFailed(ILogger logger, string step, Exception exception);
}
