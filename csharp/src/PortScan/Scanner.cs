using System.Net;
using System.Net.Sockets;
using System.Text;

namespace PortScan;

public enum PortState
{
    Open,
    Closed,
    Filtered,
    Error,
}

public static class PortStateExtensions
{
    public static string Name(this PortState state) => state switch
    {
        PortState.Open => "open",
        PortState.Closed => "closed",
        PortState.Filtered => "filtered",
        PortState.Error => "error",
        _ => "error",
    };
}

public sealed record PortResult
{
    public required ushort Port { get; init; }

    public required PortState State { get; init; }

    public required long Ms { get; init; }

    public string Banner { get; init; } = string.Empty;
}

public sealed record ScanConfig
{
    public required IPAddress Address { get; init; }

    public required TimeSpan Timeout { get; init; }

    public bool Banner { get; init; }
}

public static class Scanner
{
    private const int BannerMaxChars = 120;
    private const int BannerReadBytes = 1024;
    private const int BannerWaitMs = 500;
    private static readonly byte[] HttpProbe = Encoding.ASCII.GetBytes("HEAD / HTTP/1.0\r\n\r\n");

    // mstcpip.h: TCP_INITIAL_RTO_NO_SYN_RETRANSMISSIONS is ((UCHAR)-2), i.e. 0xFE.
    // Without it, Windows waits out its default SYN retry schedule (~2s) even
    // for an instantly-refused loopback connection.
    private const byte NoSynRetransmissions = 0xfe;
    private const ushort UnspecifiedRtt = 0xffff;
    private const int SioTcpInitialRto = unchecked((int)0x98000011);

    public static bool IsHttpPort(int port) => port is 80 or 8000 or 8080 or 8888;

    public static string SanitizeBanner(ReadOnlySpan<byte> data)
    {
        var start = 0;
        while (start < data.Length && (data[start] == (byte)'\r' || data[start] == (byte)'\n' || data[start] == (byte)' '))
        {
            start++;
        }

        var builder = new StringBuilder();
        for (var i = start; i < data.Length; i++)
        {
            var value = data[i];
            if (value is (byte)'\r' or (byte)'\n')
            {
                break;
            }
            if (builder.Length >= BannerMaxChars)
            {
                break;
            }
            builder.Append(value is >= 0x20 and <= 0x7e ? (char)value : '.');
        }

        while (builder.Length > 0 && builder[^1] == ' ')
        {
            builder.Length--;
        }
        return builder.ToString();
    }

    private static void DisableSynRetransmission(Socket socket)
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }
        var parameters = new byte[4];
        BitConverter.GetBytes(UnspecifiedRtt).CopyTo(parameters, 0);
        parameters[2] = NoSynRetransmissions;
        parameters[3] = 0;
        try
        {
            socket.IOControl(SioTcpInitialRto, parameters, null);
        }
        catch (SocketException)
        {
            // best-effort: worst case we fall back to the OS default retry timing
        }
    }

    private static PortState ClassifyError(SocketException error) => error.SocketErrorCode switch
    {
        SocketError.ConnectionRefused => PortState.Closed,
        SocketError.TimedOut or SocketError.HostUnreachable or SocketError.NetworkUnreachable or
            SocketError.HostDown or SocketError.AccessDenied => PortState.Filtered,
        _ => PortState.Error,
    };

    public static async Task<PortResult> ScanPortAsync(ScanConfig config, ushort port)
    {
        var stopwatch = System.Diagnostics.Stopwatch.StartNew();
        using var socket = new Socket(config.Address.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
        DisableSynRetransmission(socket);

        using var timeoutCts = new CancellationTokenSource(config.Timeout);
        try
        {
            await socket.ConnectAsync(new IPEndPoint(config.Address, port), timeoutCts.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (timeoutCts.IsCancellationRequested)
        {
            return new PortResult { Port = port, State = PortState.Filtered, Ms = stopwatch.ElapsedMilliseconds };
        }
        catch (SocketException error)
        {
            return new PortResult { Port = port, State = ClassifyError(error), Ms = stopwatch.ElapsedMilliseconds };
        }

        var ms = stopwatch.ElapsedMilliseconds;
        var banner = config.Banner ? await ReadBannerAsync(socket, port, config.Timeout).ConfigureAwait(false) : string.Empty;
        return new PortResult { Port = port, State = PortState.Open, Ms = ms, Banner = banner };
    }

    private static async Task<string> ReadBannerAsync(Socket socket, int port, TimeSpan timeout)
    {
        var wait = timeout < TimeSpan.FromMilliseconds(BannerWaitMs) ? timeout : TimeSpan.FromMilliseconds(BannerWaitMs);

        if (IsHttpPort(port))
        {
            try
            {
                await socket.SendAsync(HttpProbe, SocketFlags.None).ConfigureAwait(false);
            }
            catch (SocketException)
            {
                return string.Empty;
            }
        }

        using var cts = new CancellationTokenSource(wait);
        var buffer = new byte[BannerReadBytes];
        try
        {
            var received = await socket.ReceiveAsync(buffer, SocketFlags.None, cts.Token).ConfigureAwait(false);
            return received > 0 ? SanitizeBanner(buffer.AsSpan(0, received)) : string.Empty;
        }
        catch (Exception exception) when (exception is OperationCanceledException or SocketException)
        {
            return string.Empty;
        }
    }

    public static async Task<IReadOnlyList<PortResult>> ScanPortsAsync(ScanConfig config, IReadOnlyList<ushort> ports, int concurrency)
    {
        ArgumentNullException.ThrowIfNull(ports);

        var results = new PortResult[ports.Count];
        using var semaphore = new SemaphoreSlim(Math.Max(concurrency, 1));

        var tasks = new Task[ports.Count];
        for (var i = 0; i < ports.Count; i++)
        {
            var index = i;
            tasks[index] = Task.Run(async () =>
            {
                await semaphore.WaitAsync().ConfigureAwait(false);
                try
                {
                    results[index] = await ScanPortAsync(config, ports[index]).ConfigureAwait(false);
                }
                finally
                {
                    semaphore.Release();
                }
            });
        }

        await Task.WhenAll(tasks).ConfigureAwait(false);
        return results;
    }
}
