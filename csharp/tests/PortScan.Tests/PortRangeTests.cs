using System.Net;
using System.Net.Sockets;

using Xunit;

namespace PortScan.Tests;

public class PortRangeTests
{
    [Fact]
    public void AcceptsValidSpecs()
    {
        Assert.Equal(new ushort[] { 22 }, PortRange.Parse("22"));
        Assert.Equal(Enumerable.Range(1, 10).Select(v => (ushort)v), PortRange.Parse("1-10"));
        Assert.Equal(new ushort[] { 22, 80, 443 }, PortRange.Parse("22,80,443"));
        Assert.Equal(new ushort[] { 22, 80 }, PortRange.Parse("80,22,80"));
        Assert.Equal(5, PortRange.Parse("1-3,2-5").Count);
        Assert.Equal(new ushort[] { 65535 }, PortRange.Parse("65535"));
        Assert.Equal(65535, PortRange.Parse("1-65535").Count);
    }

    [Theory]
    [InlineData("")]
    [InlineData("0")]
    [InlineData("65536")]
    [InlineData("70000")]
    [InlineData("100-1")]
    [InlineData("1-")]
    [InlineData("-5")]
    [InlineData("a")]
    [InlineData("22,,80")]
    [InlineData("22,")]
    [InlineData(",22")]
    [InlineData("1-2-3")]
    [InlineData("-")]
    [InlineData("12x")]
    [InlineData(" 22")]
    [InlineData("99999999999999999999")]
    public void RejectsInvalidSpecs(string spec)
    {
        Assert.Throws<PortListParseException>(() => PortRange.Parse(spec));
    }
}

public class ArgsTests
{
    [Fact]
    public void DefaultsAreApplied()
    {
        var options = Args.Parse(new[] { "127.0.0.1" });

        Assert.Equal("127.0.0.1", options.Target);
        Assert.Equal("1-1024", options.PortsSpec);
        Assert.Equal(TimeSpan.FromMilliseconds(800), options.Timeout);
        Assert.Equal(500, options.Concurrency);
        Assert.False(options.Banner);
        Assert.False(options.Confirmed);
        Assert.Equal(ReportFormat.Table, options.Format);
    }

    [Fact]
    public void FullCommandLineIsParsed()
    {
        var options = Args.Parse(new[]
        {
            "localhost", "--ports", "22,80", "--timeout", "250", "--concurrency", "64", "--banner",
            "--format", "json", "--yes-i-own-this",
        });

        Assert.Equal("localhost", options.Target);
        Assert.Equal("22,80", options.PortsSpec);
        Assert.Equal(TimeSpan.FromMilliseconds(250), options.Timeout);
        Assert.Equal(64, options.Concurrency);
        Assert.True(options.Banner);
        Assert.True(options.Confirmed);
        Assert.Equal(ReportFormat.Json, options.Format);
    }

    [Theory]
    [MemberData(nameof(InvalidArgumentSets))]
    public void RejectsBadInput(string[] arguments)
    {
        Assert.Throws<ArgumentParseException>(() => Args.Parse(arguments));
    }

    public static IEnumerable<object[]> InvalidArgumentSets()
    {
        yield return new object[] { Array.Empty<string>() };
        yield return new object[] { new[] { "a", "b" } };
        yield return new object[] { new[] { "a", "--zoom" } };
        yield return new object[] { new[] { "a", "--ports" } };
        yield return new object[] { new[] { "a", "--timeout", "10" } };
        yield return new object[] { new[] { "a", "--concurrency", "0" } };
        yield return new object[] { new[] { "a", "--timeout", "abc" } };
        yield return new object[] { new[] { "a", "--format", "xml" } };
    }

    [Fact]
    public void HelpIsRecognised()
    {
        Assert.True(Args.Parse(new[] { "--help" }).Help);
    }
}

public class LocalAddressTests
{
    [Theory]
    [InlineData("127.0.0.1")]
    [InlineData("10.1.2.3")]
    [InlineData("172.16.0.1")]
    [InlineData("172.31.255.255")]
    [InlineData("192.168.1.1")]
    [InlineData("169.254.1.1")]
    [InlineData("0.0.0.0")]
    [InlineData("::1")]
    [InlineData("fe80::1")]
    [InlineData("fd00::1")]
    [InlineData("::ffff:10.0.0.1")]
    public void RecognisesLocalAddresses(string text)
    {
        Assert.True(LocalAddress.IsLocal(IPAddress.Parse(text)));
    }

    [Theory]
    [InlineData("8.8.8.8")]
    [InlineData("1.1.1.1")]
    [InlineData("172.32.0.1")]
    [InlineData("172.15.0.1")]
    [InlineData("192.169.0.1")]
    [InlineData("2001:4860:4860::8888")]
    [InlineData("::ffff:8.8.8.8")]
    public void RecognisesNonLocalAddresses(string text)
    {
        Assert.False(LocalAddress.IsLocal(IPAddress.Parse(text)));
    }
}

public class ScannerTests
{
    [Fact]
    public void SanitizeBannerBehaviour()
    {
        Assert.Equal("SSH-2.0-OpenSSH_9.6", Scanner.SanitizeBanner("SSH-2.0-OpenSSH_9.6\r\nextra"u8.ToArray()));
        Assert.Equal("A.B.C", Scanner.SanitizeBanner(new byte[] { (byte)'A', 0x01, (byte)'B', 0xff, (byte)'C' }));
        Assert.Equal("220 hello", Scanner.SanitizeBanner("\r\n  220 hello  \r\n"u8.ToArray()));
        Assert.Equal(120, Scanner.SanitizeBanner(Enumerable.Repeat((byte)'x', 300).ToArray()).Length);
        Assert.Equal(string.Empty, Scanner.SanitizeBanner(ReadOnlySpan<byte>.Empty));
    }

    [Fact]
    public void HttpPortsAreRecognised()
    {
        Assert.True(Scanner.IsHttpPort(80) && Scanner.IsHttpPort(8080) && Scanner.IsHttpPort(8000) && Scanner.IsHttpPort(8888));
        Assert.False(Scanner.IsHttpPort(22) || Scanner.IsHttpPort(443));
    }

    private static (Socket Listener, ushort Port) OpenListener()
    {
        var listener = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        listener.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        listener.Listen(512);
        var port = (ushort)((IPEndPoint)listener.LocalEndPoint!).Port;
        return (listener, port);
    }

    private static ScanConfig MakeConfig(bool banner) => new()
    {
        Address = IPAddress.Loopback,
        Timeout = TimeSpan.FromMilliseconds(2000),
        Banner = banner,
    };

    [Fact]
    public async Task OpenAndClosedPortsAreDetected()
    {
        var (listener, port) = OpenListener();

        var openResult = await Scanner.ScanPortAsync(MakeConfig(false), port);
        Assert.Equal(PortState.Open, openResult.State);

        listener.Dispose();
        var closedResult = await Scanner.ScanPortAsync(MakeConfig(false), port);
        Assert.Equal(PortState.Closed, closedResult.State);
    }

    [Fact]
    public async Task BannerGrabReadsServerText()
    {
        var (listener, port) = OpenListener();
        var serverTask = Task.Run(async () =>
        {
            using var client = await listener.AcceptAsync();
            await client.SendAsync("220 izci test ready\r\n"u8.ToArray(), SocketFlags.None);
            var sink = new byte[16];
            using var cts = new CancellationTokenSource(500);
            try
            {
                await client.ReceiveAsync(sink, SocketFlags.None, cts.Token);
            }
            catch (OperationCanceledException)
            {
            }
        });

        var result = await Scanner.ScanPortAsync(MakeConfig(true), port);
        await serverTask;
        listener.Dispose();

        Assert.Equal(PortState.Open, result.State);
        Assert.Equal("220 izci test ready", result.Banner);
    }

    [Fact]
    public async Task RepeatedScansAreStable()
    {
        const int RangeSize = 200;
        const int Rounds = 20;

        var (listener, port) = OpenListener();
        var config = MakeConfig(false);
        var first = (ushort)(port - RangeSize / 2);
        var ports = Enumerable.Range(0, RangeSize).Select(offset => (ushort)(first + offset)).ToList();

        var baseline = await Scanner.ScanPortsAsync(config, ports, 64);
        Assert.Equal(PortState.Open, baseline[port - first].State);

        for (var round = 0; round < Rounds; round++)
        {
            var current = await Scanner.ScanPortsAsync(config, ports, 64);
            for (var i = 0; i < baseline.Count; i++)
            {
                Assert.Equal(baseline[i].State, current[i].State);
            }
        }

        listener.Dispose();
    }
}

public class ReportTests
{
    private static PortResult Make(ushort port, PortState state, long ms, string banner) => new()
    {
        Port = port,
        State = state,
        Ms = ms,
        Banner = banner,
    };

    [Fact]
    public void Counts()
    {
        var items = new[]
        {
            Make(22, PortState.Open, 1, ""),
            Make(23, PortState.Closed, 0, ""),
            Make(24, PortState.Closed, 0, ""),
            Make(25, PortState.Filtered, 800, ""),
            Make(26, PortState.Error, 0, ""),
        };

        var counts = Report.CountResults(items);

        Assert.Equal(1, counts.Open);
        Assert.Equal(2, counts.Closed);
        Assert.Equal(1, counts.Filtered);
        Assert.Equal(1, counts.Errors);
    }

    [Fact]
    public void JsonLayoutMatchesExpectedFormat()
    {
        var items = new[]
        {
            Make(22, PortState.Open, 2, "SSH-2.0-test"),
            Make(23, PortState.Closed, 0, ""),
            Make(24, PortState.Filtered, 800, ""),
        };
        var report = new ScanReport { Target = "host", Address = "127.0.0.1", Results = items, ElapsedMs = 9 };

        var text = Report.WriteJson(report);

        Assert.Equal(
            "{\"target\":\"host\",\"address\":\"127.0.0.1\",\"scanned\":3,\"open\":[{\"port\":22,\"state\":\"open\",\"banner\":\"SSH-2.0-test\",\"ms\":2}],\"closed\":1,\"filtered\":1,\"errors\":0,\"elapsed_ms\":9}\n",
            text);
    }

    [Fact]
    public void JsonEscapesBanner()
    {
        var items = new[] { Make(80, PortState.Open, 1, "say \"hi\" \\ done") };
        var report = new ScanReport { Target = "t", Address = "127.0.0.1", Results = items, ElapsedMs = 1 };

        var text = Report.WriteJson(report);

        Assert.Contains("\"banner\":\"say \\\"hi\\\" \\\\ done\"", text, StringComparison.Ordinal);
    }

    [Fact]
    public void TableListsOnlyOpenPorts()
    {
        var items = new[]
        {
            Make(22, PortState.Open, 3, "SSH-2.0-test"),
            Make(23, PortState.Closed, 0, ""),
        };
        var report = new ScanReport { Target = "host", Address = "127.0.0.1", Results = items, ElapsedMs = 5 };

        var text = Report.WriteTable(report);

        Assert.Contains("SSH-2.0-test", text, StringComparison.Ordinal);
        Assert.Contains("scanned 2 ports on host (127.0.0.1) in 5 ms: 1 open, 1 closed, 0 filtered", text, StringComparison.Ordinal);
        Assert.DoesNotContain("closed  ", text, StringComparison.Ordinal);
    }
}
