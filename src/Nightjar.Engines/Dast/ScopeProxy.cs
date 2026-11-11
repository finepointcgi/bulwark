using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using Nightjar.Core.Dast;

namespace Nightjar.Engines.Dast;

/// <summary>One request the proxy saw, written to the request log kept with every pentest report.</summary>
public sealed record ProxyLogEntry(DateTimeOffset Time, string Method, string Url, bool Allowed, string? Reason);

/// <summary>
/// HTTP proxy that every DAST engine is pointed at. It is the enforcement point for the scope:
/// plain-HTTP requests are checked by method, host, port and normalized path; HTTPS tunnels
/// (CONNECT) are checked by host and port, since the proxy does not decrypt TLS. Requests are
/// rate limited, and every request, allowed or blocked, is logged.
/// </summary>
public sealed class ScopeProxy : IAsyncDisposable
{
    private const int MaxHeaderBytes = 64 * 1024;
    private static readonly JsonSerializerOptions LogJson = new(JsonSerializerDefaults.Web);

    private readonly PentestScope _scope;
    private readonly TcpListener _listener;
    private readonly RequestPacer _limiter;
    private readonly StreamWriter _log;
    private readonly CancellationTokenSource _stop = new();
    private Task? _acceptLoop;
    private int _allowed;
    private int _blocked;

    public ScopeProxy(PentestScope scope, IPAddress bindAddress, string logPath)
    {
        _scope = scope;
        _listener = new TcpListener(bindAddress, 0);
        _limiter = new RequestPacer(scope.MaxRequestsPerSecond);
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(logPath))!);
        _log = new StreamWriter(logPath, append: false) { AutoFlush = true };
        LogPath = logPath;
    }

    public int Port => ((IPEndPoint)_listener.LocalEndpoint).Port;
    public string LogPath { get; }
    public int Allowed => _allowed;
    public int Blocked => _blocked;

    public void Start()
    {
        _listener.Start();
        _acceptLoop = AcceptLoopAsync(_stop.Token);
    }

    public async ValueTask DisposeAsync()
    {
        await _stop.CancelAsync();
        _listener.Stop();
        if (_acceptLoop is not null)
        {
            try { await _acceptLoop; } catch (OperationCanceledException) { }
        }

        lock (_log) { _log.Dispose(); }
        _stop.Dispose();
    }

    private async Task AcceptLoopAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            TcpClient client;
            try
            {
                client = await _listener.AcceptTcpClientAsync(cancellationToken);
            }
            catch (Exception e) when (e is OperationCanceledException or ObjectDisposedException or SocketException)
            {
                return;
            }

            _ = HandleAsync(client, cancellationToken);
        }
    }

    private async Task HandleAsync(TcpClient client, CancellationToken cancellationToken)
    {
        using var _ = client;
        try
        {
            var clientStream = client.GetStream();
            var (head, leftover) = await ReadHeadAsync(clientStream, cancellationToken);
            if (head is null)
            {
                return;
            }

            var lines = head.Split("\r\n");
            var requestLine = lines[0].Split(' ');
            if (requestLine.Length < 3)
            {
                await RespondAsync(clientStream, 400, "Malformed request line", cancellationToken);
                return;
            }

            var method = requestLine[0].ToUpperInvariant();
            if (method == "CONNECT")
            {
                await TunnelAsync(clientStream, requestLine[1], leftover, cancellationToken);
            }
            else
            {
                await ForwardAsync(clientStream, method, requestLine[1], requestLine[2], lines.Skip(1), leftover, cancellationToken);
            }
        }
        catch (Exception e) when (e is IOException or SocketException or OperationCanceledException or ObjectDisposedException)
        {
            // Client or upstream went away; nothing to clean up beyond the using.
        }
    }

    private async Task TunnelAsync(NetworkStream clientStream, string authority, byte[] leftover, CancellationToken cancellationToken)
    {
        var separator = authority.LastIndexOf(':');
        var host = separator > 0 ? authority[..separator].Trim('[', ']') : authority;
        var port = separator > 0 && int.TryParse(authority[(separator + 1)..], out var p) ? p : 443;
        var url = $"https://{host}:{port}";

        if (!_scope.AllowsTunnel(host, port))
        {
            Record("CONNECT", url, false, $"{host}:{port} is not an https scope target");
            await RespondAsync(clientStream, 403, "Blocked by Nightjar scope", cancellationToken);
            return;
        }

        await _limiter.WaitAsync(cancellationToken);
        using var upstream = new TcpClient();
        await upstream.ConnectAsync(host, port, cancellationToken);
        Record("CONNECT", url, true, null);

        await clientStream.WriteAsync("HTTP/1.1 200 Connection Established\r\n\r\n"u8.ToArray(), cancellationToken);
        var upstreamStream = upstream.GetStream();
        if (leftover.Length > 0)
        {
            await upstreamStream.WriteAsync(leftover, cancellationToken);
        }

        await PipeAsync(clientStream, upstreamStream, cancellationToken);
    }

    private async Task ForwardAsync(
        NetworkStream clientStream, string method, string target, string version,
        IEnumerable<string> headers, byte[] leftover, CancellationToken cancellationToken)
    {
        if (!Uri.TryCreate(target, UriKind.Absolute, out var uri) || uri.Scheme != "http")
        {
            Record(method, target, false, "proxy requests must use an absolute http:// URL");
            await RespondAsync(clientStream, 400, "Expected an absolute http:// URL", cancellationToken);
            return;
        }

        var decision = _scope.Check(method, uri);
        if (!decision.Allowed)
        {
            Record(method, uri.ToString(), false, decision.Reason);
            await RespondAsync(clientStream, 403, $"Blocked by Nightjar scope: {decision.Reason}", cancellationToken);
            return;
        }

        await _limiter.WaitAsync(cancellationToken);
        using var upstream = new TcpClient();
        await upstream.ConnectAsync(uri.Host, uri.Port, cancellationToken);
        Record(method, uri.ToString(), true, null);

        // One request per upstream connection keeps the scope check per request: a client can't
        // send a second, unchecked request down an already-approved keep-alive connection.
        var request = new StringBuilder();
        request.Append(method).Append(' ').Append(uri.PathAndQuery).Append(' ').Append(version).Append("\r\n");
        var hasHost = false;
        foreach (var header in headers.Where(h => h.Length > 0))
        {
            var name = header.Split(':', 2)[0].Trim();
            if (name.StartsWith("Proxy-", StringComparison.OrdinalIgnoreCase)
                || name.Equals("Connection", StringComparison.OrdinalIgnoreCase)
                || name.Equals("Keep-Alive", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            hasHost |= name.Equals("Host", StringComparison.OrdinalIgnoreCase);
            request.Append(header).Append("\r\n");
        }

        if (!hasHost)
        {
            request.Append("Host: ").Append(uri.Authority).Append("\r\n");
        }

        request.Append("Connection: close\r\n\r\n");

        var upstreamStream = upstream.GetStream();
        await upstreamStream.WriteAsync(Encoding.ASCII.GetBytes(request.ToString()), cancellationToken);
        if (leftover.Length > 0)
        {
            await upstreamStream.WriteAsync(leftover, cancellationToken);
        }

        await PipeAsync(clientStream, upstreamStream, cancellationToken);
    }

    /// <summary>Copies both directions until the upstream side finishes.</summary>
    private static async Task PipeAsync(NetworkStream client, NetworkStream upstream, CancellationToken cancellationToken)
    {
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var up = client.CopyToAsync(upstream, linked.Token);
        var down = upstream.CopyToAsync(client, linked.Token);
        await Task.WhenAny(up, down);
        if (down.IsCompleted)
        {
            await linked.CancelAsync();
        }
        else
        {
            // Client finished sending; let the response finish.
            await down;
        }
    }

    private static async Task<(string? Head, byte[] Leftover)> ReadHeadAsync(NetworkStream stream, CancellationToken cancellationToken)
    {
        var buffer = new byte[8192];
        using var collected = new MemoryStream();
        while (collected.Length < MaxHeaderBytes)
        {
            var read = await stream.ReadAsync(buffer, cancellationToken);
            if (read == 0)
            {
                return (null, []);
            }

            collected.Write(buffer, 0, read);
            var bytes = collected.GetBuffer().AsSpan(0, (int)collected.Length);
            var end = bytes.IndexOf("\r\n\r\n"u8);
            if (end >= 0)
            {
                return (Encoding.ASCII.GetString(bytes[..end]), bytes[(end + 4)..].ToArray());
            }
        }

        return (null, []);
    }

    private static async Task RespondAsync(NetworkStream stream, int status, string message, CancellationToken cancellationToken)
    {
        var reason = status switch { 400 => "Bad Request", 403 => "Forbidden", _ => "Error" };
        var body = Encoding.UTF8.GetBytes(message + "\n");
        var head = $"HTTP/1.1 {status} {reason}\r\nContent-Type: text/plain\r\nContent-Length: {body.Length}\r\nConnection: close\r\n\r\n";
        await stream.WriteAsync(Encoding.ASCII.GetBytes(head), cancellationToken);
        await stream.WriteAsync(body, cancellationToken);
    }

    private void Record(string method, string url, bool allowed, string? reason)
    {
        if (allowed) { Interlocked.Increment(ref _allowed); } else { Interlocked.Increment(ref _blocked); }
        var line = JsonSerializer.Serialize(new ProxyLogEntry(DateTimeOffset.UtcNow, method, url, allowed, reason), LogJson);
        lock (_log)
        {
            _log.WriteLine(line);
        }
    }
}

/// <summary>Spaces requests evenly so the target never sees more than the scope's rate.</summary>
internal sealed class RequestPacer(int perSecond)
{
    private readonly TimeSpan _interval = TimeSpan.FromSeconds(1.0 / Math.Max(1, perSecond));
    private readonly Lock _gate = new();
    private DateTimeOffset _next = DateTimeOffset.MinValue;

    public Task WaitAsync(CancellationToken cancellationToken)
    {
        TimeSpan delay;
        lock (_gate)
        {
            var now = DateTimeOffset.UtcNow;
            var slot = _next > now ? _next : now;
            _next = slot + _interval;
            delay = slot - now;
        }

        return delay > TimeSpan.Zero ? Task.Delay(delay, cancellationToken) : Task.CompletedTask;
    }
}
