using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace CrioFire.Core.Api;

/// <summary>What a client of the API may do.</summary>
public enum ClientRights
{
    /// <summary>Read only.</summary>
    ReadOnly,

    /// <summary>CrioFire's own app from the install folder: may change rules unless tamper protection is on.</summary>
    CrioFireApp,

    /// <summary>An elevated administrator: may change anything, including tamper protection.</summary>
    Administrator,
}

/// <summary>Who may change rules through the API. Pure logic, unit-tested.</summary>
public static class ApiAuthorization
{
    public static ClientRights Rights(bool clientIsElevatedAdmin, string? clientPath, string trustedDirectory) =>
        clientIsElevatedAdmin ? ClientRights.Administrator
        : CanWrite(false, clientPath, trustedDirectory) ? ClientRights.CrioFireApp
        : ClientRights.ReadOnly;

    /// <summary>
    /// The one program that may change rules without running elevated: the app, where a person
    /// clicks. The command line is not in this list: any program could run it, so
    /// "criofire allow evil.exe" would let a program allow itself. From the command line, changes
    /// need an administrator prompt.
    /// </summary>
    public static IReadOnlyList<string> TrustedClientNames { get; } = ["criofire-ui.exe"];

    /// <summary>
    /// A client may change rules if it runs elevated as an administrator, or if it is CrioFire's
    /// app started from the service's own folder (the install folder, which only administrators
    /// can write to).
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

    /// <summary>The longest request, in bytes: a rules file for import can hold many rules.</summary>
    public const int MaxRequestBytes = 4 * 1024 * 1024;

    /// <summary>Connections served at once, in all and for one Windows account, so no account can use up the service's memory or everyone's turn.</summary>
    public const int MaxClients = 96;
    public const int MaxClientsPerUser = 24;

    private readonly System.Threading.Channels.Channel<bool> _slots = System.Threading.Channels.Channel.CreateBounded<bool>(MaxClients);   // a place per connection
    private readonly Lock _clientsGate = new();
    private readonly Dictionary<string, int> _clients = new(StringComparer.Ordinal);

    private readonly string _trustedDirectory = trustedDirectory ?? AppContext.BaseDirectory;

    /// <summary>Accepts clients until <paramref name="cancellationToken"/> is cancelled.</summary>
    public async Task RunAsync(CancellationToken cancellationToken)
    {
        // Compile the call made as the client now, as the service (it finds no token here).
        if (OpenThreadToken(GetCurrentThread(), TokenQuery, openAsSelf: true, out var unused))
        {
            CloseHandle(unused);
        }

        var first = true;
        while (!cancellationToken.IsCancellationRequested)
        {
            // One listening pipe plus the clients being served never exceed MaxClients.
            try
            {
                await _slots.Writer.WriteAsync(true, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                break;
            }

            NamedPipeServerStream pipe;
            try
            {
                pipe = CreatePipe(first);
            }
            catch (Exception ex) when (!first && ex is IOException or UnauthorizedAccessException)
            {
                // Clients are being served, so the name is ours; Windows was out of something for a moment.
                _slots.Reader.TryRead(out _);
                await Task.Delay(TimeSpan.FromSeconds(1), cancellationToken).ConfigureAwait(false);
                continue;
            }
            catch
            {
                _slots.Reader.TryRead(out _);
                throw;
            }

            first = false;
            try
            {
                await pipe.WaitForConnectionAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                await pipe.DisposeAsync().ConfigureAwait(false);
                _slots.Reader.TryRead(out _);
                break;
            }
            catch (IOException)
            {
                // The client was gone before it was greeted.
                await pipe.DisposeAsync().ConfigureAwait(false);
                _slots.Reader.TryRead(out _);
                continue;
            }

            _ = Task.Run(
                async () =>
                {
                    try
                    {
                        await ServeClientAsync(pipe, cancellationToken).ConfigureAwait(false);
                    }
                    finally
                    {
                        _slots.Reader.TryRead(out _);
                    }
                },
                CancellationToken.None);
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
            pipeName, PipeDirection.InOut, MaxClients,
            PipeTransmissionMode.Byte, options, 0, 0, security);
    }

    private async Task ServeClientAsync(NamedPipeServerStream pipe, CancellationToken cancellationToken)
    {
        string? user = null;
        var counted = false;
        await using (pipe.ConfigureAwait(false))
        {
            try
            {
                var elevated = ClientIdentity(pipe, out user);
                if (!Enter(user))
                {
                    return;   // this account already holds its share of connections
                }

                counted = true;

                var rights = ApiAuthorization.Rights(elevated, ClientPath(pipe), _trustedDirectory);
                uint? session = GetNamedPipeClientSessionId(pipe.SafePipeHandle, out var sessionId) ? sessionId : null;
                var reader = new RequestReader(pipe, MaxRequestBytes);
                await using var writer = new StreamWriter(pipe, new UTF8Encoding(false), leaveOpen: true) { AutoFlush = true, NewLine = "\n" };

                while (!cancellationToken.IsCancellationRequested && pipe.IsConnected)
                {
                    string? line;
                    try
                    {
                        line = await reader.ReadLineAsync(cancellationToken).ConfigureAwait(false);
                    }
                    catch (InvalidDataException)
                    {
                        // Longer than any request: answer and hang up, without reading the rest.
                        await writer.WriteLineAsync(ApiJson.Serialize(ApiResponse.Failure("Request too large.")).AsMemory(), cancellationToken).ConfigureAwait(false);
                        break;
                    }

                    if (line is null)
                    {
                        break;
                    }

                    ApiRequest? request = null;
                    try
                    {
                        request = ApiJson.DeserializeRequest(line);
                    }
                    catch (System.Text.Json.JsonException)
                    {
                    }

                    var response = request is null ? ApiResponse.Failure("Malformed request.") : handler.Handle(request, rights, session);
                    await writer.WriteLineAsync(ApiJson.Serialize(response).AsMemory(), cancellationToken).ConfigureAwait(false);
                }
            }
            catch (Exception ex) when (ex is IOException or OperationCanceledException or ObjectDisposedException)
            {
                // Client went away or the service is stopping.
            }
            finally
            {
                if (counted)
                {
                    Leave(user);
                }
            }
        }
    }

    /// <summary>Counts a connection for its Windows account; false when the account has too many open.</summary>
    private bool Enter(string? user)
    {
        lock (_clientsGate)
        {
            var key = user ?? string.Empty;
            var open = _clients.GetValueOrDefault(key);
            if (open >= MaxClientsPerUser)
            {
                return false;
            }

            _clients[key] = open + 1;
            return true;
        }
    }

    private void Leave(string? user)
    {
        lock (_clientsGate)
        {
            var key = user ?? string.Empty;
            if (_clients.TryGetValue(key, out var open))
            {
                if (open <= 1)
                {
                    _clients.Remove(key);
                }
                else
                {
                    _clients[key] = open - 1;
                }
            }
        }
    }

    /// <summary>
    /// Whether the client runs elevated as an administrator. While the thread acts as the client
    /// it holds an identification-only token, with which nothing can be opened: not even a .NET
    /// assembly that happens to be needed for the first time. (That made an elevated client look
    /// like an ordinary one in the service, where nothing had loaded those assemblies yet.) So the
    /// only thing done as the client is one Windows call to pick up its token; the token is
    /// examined afterwards, as the service.
    /// </summary>
    private static bool ClientIdentity(NamedPipeServerStream pipe, out string? user)
    {
        user = null;
        var token = IntPtr.Zero;
        try
        {
            pipe.RunAsClient(() =>
            {
                if (!OpenThreadToken(GetCurrentThread(), TokenQuery | TokenDuplicate, openAsSelf: true, out token))
                {
                    token = IntPtr.Zero;
                }
            });
            if (token == IntPtr.Zero)
            {
                return false;
            }

            // A non-elevated administrator's token has the group for deny only: not in the role.
            using var identity = new WindowsIdentity(token);
            user = identity.User?.Value;
            return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException or System.Security.SecurityException or ArgumentException)
        {
            return false;
        }
        finally
        {
            if (token != IntPtr.Zero)
            {
                CloseHandle(token);
            }
        }
    }

    /// <summary>
    /// The client's program, as Windows itself knows it. (Not Process.MainModule: that reads the
    /// path out of the client's own memory, where the client can write any path it likes.)
    /// </summary>
    private static string? ClientPath(NamedPipeServerStream pipe)
    {
        if (!GetNamedPipeClientProcessId(pipe.SafePipeHandle, out var pid))
        {
            return null;
        }

        var process = OpenProcess(ProcessQueryLimitedInformation, inherit: false, pid);
        if (process == IntPtr.Zero)
        {
            return null;
        }

        try
        {
            var buffer = new char[32768];
            var length = (uint)buffer.Length;
            return QueryFullProcessImageNameW(process, 0, buffer, ref length) && length > 0 ? new string(buffer, 0, (int)length) : null;
        }
        finally
        {
            CloseHandle(process);
        }
    }

    private const uint ProcessQueryLimitedInformation = 0x1000;

    [LibraryImport("kernel32.dll", SetLastError = true)]
    private static partial IntPtr OpenProcess(uint access, [MarshalAs(UnmanagedType.Bool)] bool inherit, uint processId);

    [LibraryImport("kernel32.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool QueryFullProcessImageNameW(IntPtr process, uint flags, [Out] char[] name, ref uint size);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetNamedPipeClientProcessId(SafePipeHandle pipe, out uint clientProcessId);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetNamedPipeClientSessionId(SafePipeHandle pipe, out uint clientSessionId);

    private const uint TokenDuplicate = 0x0002;
    private const uint TokenQuery = 0x0008;

    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool OpenThreadToken(IntPtr thread, uint access, [MarshalAs(UnmanagedType.Bool)] bool openAsSelf, out IntPtr token);

    [LibraryImport("kernel32.dll")]
    private static partial IntPtr GetCurrentThread();

    [LibraryImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CloseHandle(IntPtr handle);
}

/// <summary>
/// Reads requests, one line each, without ever holding more than <paramref name="maxBytes"/> of
/// a line: a client that sends an endless line is cut off instead of filling the service's memory.
/// </summary>
public sealed class RequestReader(Stream stream, int maxBytes)
{
    private readonly byte[] _buffer = new byte[16 * 1024];
    private readonly System.Buffers.ArrayBufferWriter<byte> _line = new();
    private int _start;
    private int _end;

    /// <summary>The next line (without its line break), or null at the end. A line that is too long throws <see cref="InvalidDataException"/>.</summary>
    public async Task<string?> ReadLineAsync(CancellationToken cancellationToken = default)
    {
        while (true)
        {
            var newline = Array.IndexOf(_buffer, (byte)'\n', _start, _end - _start);
            var take = (newline >= 0 ? newline : _end) - _start;
            if (_line.WrittenCount + take > maxBytes)
            {
                throw new InvalidDataException("The request is too large.");
            }

            System.Buffers.BuffersExtensions.Write(_line, _buffer.AsSpan(_start, take));
            if (newline >= 0)
            {
                _start = newline + 1;
                return Take();
            }

            _start = 0;
            _end = await stream.ReadAsync(_buffer, cancellationToken).ConfigureAwait(false);
            if (_end == 0)
            {
                return _line.WrittenCount == 0 ? null : Take();
            }
        }
    }

    private string Take()
    {
        var bytes = _line.WrittenSpan;
        if (bytes.Length > 0 && bytes[^1] == (byte)'\r')
        {
            bytes = bytes[..^1];
        }

        var text = Encoding.UTF8.GetString(bytes);
        _line.ResetWrittenCount();
        return text;
    }
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
            if (!ServedByCrioFire(pipe))
            {
                // Another program took the pipe's name while the service was not running: not the service.
                pipe.Dispose();
                return null;
            }

            return new CrioFireClient(pipe);
        }
        catch (Exception ex) when (ex is TimeoutException or IOException or UnauthorizedAccessException)
        {
            pipe.Dispose();
            return null;
        }
    }

    /// <summary>
    /// The real service's pipe belongs to SYSTEM or the Administrators group (or, for a developer's
    /// own copy, to the account asking). A pipe made by any other account is somebody posing as
    /// the service, to show made-up answers.
    /// </summary>
    private static bool ServedByCrioFire(NamedPipeClientStream pipe)
    {
        if (!OperatingSystem.IsWindows())
        {
            return true;
        }

        try
        {
            if (pipe.GetAccessControl().GetOwner(typeof(SecurityIdentifier)) is not SecurityIdentifier owner)
            {
                return false;
            }

            using var me = WindowsIdentity.GetCurrent();
            return owner.IsWellKnown(WellKnownSidType.LocalSystemSid)
                || owner.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid)
                || (me.User is { } mine && owner.Equals(mine));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException or System.Security.SecurityException)
        {
            return false;
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
