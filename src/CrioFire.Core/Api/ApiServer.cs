using System.Diagnostics;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace CrioFire.Core.Api;

/// <summary>Who may change rules through the API. Pure logic, unit-tested.</summary>
public static class ApiAuthorization
{
    /// <summary>CrioFire's own client programs.</summary>
    public static IReadOnlyList<string> TrustedClientNames { get; } = ["criofire.exe", "criofire-ui.exe"];

    /// <summary>
    /// A client may change rules if it runs elevated as an administrator, or if it is one of
    /// CrioFire's own programs started from the service's own folder (the install folder, which
    /// only administrators can write to).
    /// </summary>
    public static bool CanWrite(bool clientIsElevatedAdmin, string? clientPath, string trustedDirectory)
    {
        if (clientIsElevatedAdmin)
        {
            return true;
        }

        if (string.IsNullOrEmpty(clientPath) || string.IsNullOrEmpty(trustedDirectory))
        {
            return false;
        }

        string full, directory;
        try
        {
            full = Path.GetFullPath(clientPath);
            directory = Path.TrimEndingDirectorySeparator(Path.GetFullPath(trustedDirectory));
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return false;
        }

        return string.Equals(Path.GetDirectoryName(full), directory, StringComparison.OrdinalIgnoreCase)
            && TrustedClientNames.Contains(Path.GetFileName(full), StringComparer.OrdinalIgnoreCase);
    }
}

/// <summary>
/// Serves the local API on a named pipe. Only local, authenticated users can connect (network
/// access is denied); reads are open to them, writes follow <see cref="ApiAuthorization"/>.
/// </summary>
public sealed partial class ApiServer(ApiHandler handler, string pipeName = ApiServer.DefaultPipeName, string? trustedDirectory = null)
{
    public const string DefaultPipeName = "criofire";

    private const int MaxLineLength = 1024 * 1024;   // a rules file for import can hold many rules

    private readonly string _trustedDirectory = trustedDirectory ?? AppContext.BaseDirectory;

    /// <summary>Accepts clients until <paramref name="cancellationToken"/> is cancelled.</summary>
    public async Task RunAsync(CancellationToken cancellationToken)
    {
        var first = true;
        while (!cancellationToken.IsCancellationRequested)
        {
            var pipe = CreatePipe(first);
            first = false;
            try
            {
                await pipe.WaitForConnectionAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                await pipe.DisposeAsync().ConfigureAwait(false);
                break;
            }

            _ = Task.Run(() => ServeClientAsync(pipe, cancellationToken), CancellationToken.None);
        }
    }

    private NamedPipeServerStream CreatePipe(bool first)
    {
        var security = new PipeSecurity();
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null), PipeAccessRights.ReadWrite, AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.NetworkSid, null), PipeAccessRights.FullControl, AccessControlType.Deny));

        // The first instance must be ours: refuse to start if another process already owns the name.
        var options = PipeOptions.Asynchronous | (first ? PipeOptions.FirstPipeInstance : PipeOptions.None);
        return NamedPipeServerStreamAcl.Create(
            pipeName, PipeDirection.InOut, NamedPipeServerStream.MaxAllowedServerInstances,
            PipeTransmissionMode.Byte, options, 0, 0, security);
    }

    private async Task ServeClientAsync(NamedPipeServerStream pipe, CancellationToken cancellationToken)
    {
        await using (pipe.ConfigureAwait(false))
        {
            try
            {
                var canWrite = ApiAuthorization.CanWrite(ClientIsElevatedAdmin(pipe), ClientPath(pipe), _trustedDirectory);
                using var reader = new StreamReader(pipe, new UTF8Encoding(false), detectEncodingFromByteOrderMarks: false, leaveOpen: true);
                await using var writer = new StreamWriter(pipe, new UTF8Encoding(false), leaveOpen: true) { AutoFlush = true, NewLine = "\n" };

                while (!cancellationToken.IsCancellationRequested && pipe.IsConnected)
                {
                    var line = await reader.ReadLineAsync(cancellationToken).ConfigureAwait(false);
                    if (line is null)
                    {
                        break;
                    }

                    ApiResponse response;
                    if (line.Length > MaxLineLength)
                    {
                        response = ApiResponse.Failure("Request too large.");
                    }
                    else
                    {
                        ApiRequest? request = null;
                        try
                        {
                            request = ApiJson.DeserializeRequest(line);
                        }
                        catch (System.Text.Json.JsonException)
                        {
                        }

                        response = request is null ? ApiResponse.Failure("Malformed request.") : handler.Handle(request, canWrite);
                    }

                    await writer.WriteLineAsync(ApiJson.Serialize(response).AsMemory(), cancellationToken).ConfigureAwait(false);
                }
            }
            catch (Exception ex) when (ex is IOException or OperationCanceledException or ObjectDisposedException)
            {
                // Client went away or the service is stopping.
            }
        }
    }

    private static bool ClientIsElevatedAdmin(NamedPipeServerStream pipe)
    {
        try
        {
            // Impersonating the client gives its real token: a non-elevated admin is not in the role.
            var isAdmin = false;
            pipe.RunAsClient(() =>
            {
                using var identity = WindowsIdentity.GetCurrent(ifImpersonating: true);
                isAdmin = identity is not null && new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
            });
            return isAdmin;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException or System.Security.SecurityException)
        {
            return false;
        }
    }

    private static string? ClientPath(NamedPipeServerStream pipe)
    {
        try
        {
            if (!GetNamedPipeClientProcessId(pipe.SafePipeHandle, out var pid))
            {
                return null;
            }

            using var process = Process.GetProcessById((int)pid);
            return process.MainModule?.FileName;
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or System.ComponentModel.Win32Exception or NotSupportedException)
        {
            return null;
        }
    }

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetNamedPipeClientProcessId(SafePipeHandle pipe, out uint clientProcessId);
}

/// <summary>Client side of the local API.</summary>
public sealed class CrioFireClient : IDisposable
{
    private readonly NamedPipeClientStream _pipe;
    private readonly StreamReader _reader;
    private readonly StreamWriter _writer;

    private CrioFireClient(NamedPipeClientStream pipe)
    {
        _pipe = pipe;
        _reader = new StreamReader(pipe, new UTF8Encoding(false), detectEncodingFromByteOrderMarks: false, leaveOpen: true);
        _writer = new StreamWriter(pipe, new UTF8Encoding(false), leaveOpen: true) { AutoFlush = true, NewLine = "\n" };
    }

    /// <summary>Connects to the service; returns null if it is not running (within <paramref name="timeoutMs"/>).</summary>
    public static CrioFireClient? TryConnect(string pipeName = ApiServer.DefaultPipeName, int timeoutMs = 2000)
    {
        // Identification lets the service check who we are; it cannot act as us.
        var pipe = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut, PipeOptions.None, TokenImpersonationLevel.Identification);
        try
        {
            pipe.Connect(timeoutMs);
            return new CrioFireClient(pipe);
        }
        catch (Exception ex) when (ex is TimeoutException or IOException or UnauthorizedAccessException)
        {
            pipe.Dispose();
            return null;
        }
    }

    public ApiResponse Send(ApiRequest request)
    {
        _writer.WriteLine(ApiJson.Serialize(request));
        var line = _reader.ReadLine() ?? throw new IOException("The CrioFire service closed the connection.");
        return ApiJson.DeserializeResponse(line) ?? throw new IOException("The CrioFire service sent an empty response.");
    }

    public void Dispose()
    {
        _reader.Dispose();
        _writer.Dispose();
        _pipe.Dispose();
    }
}
