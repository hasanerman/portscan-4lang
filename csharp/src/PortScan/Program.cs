using System.Diagnostics;
using System.Net;
using System.Net.Sockets;

namespace PortScan;

public static class Program
{
    public const int ExitOk = 0;
    public const int ExitUsage = 1;
    public const int ExitUnresolved = 2;

    public static async Task<int> Main(string[] arguments)
    {
        ArgumentNullException.ThrowIfNull(arguments);

        Options options;
        try
        {
            options = Args.Parse(arguments);
        }
        catch (ArgumentParseException exception)
        {
            Console.Error.WriteLine($"error: {exception.Message}");
            Console.Error.Write(Args.Usage);
            return ExitUsage;
        }

        if (options.Help)
        {
            Console.Write(Args.Usage);
            return ExitOk;
        }

        return await PrepareAndScanAsync(options).ConfigureAwait(false);
    }

    private static async Task<int> PrepareAndScanAsync(Options options)
    {
        IReadOnlyList<ushort> ports;
        try
        {
            ports = PortRange.Parse(options.PortsSpec);
        }
        catch (PortListParseException exception)
        {
            Console.Error.WriteLine($"error: {exception.Message}");
            return ExitUsage;
        }

        IPAddress address;
        try
        {
            address = await ResolveAsync(options.Target).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is SocketException or FormatException)
        {
            Console.Error.WriteLine($"error: cannot resolve {options.Target}");
            return ExitUnresolved;
        }

        if (!LocalAddress.IsLocal(address))
        {
            if (options.Confirmed)
            {
                Console.Error.WriteLine("note: scanning a non-local target");
            }
            else
            {
                Console.Error.WriteLine(
                    $"error: {options.Target} is not a local or private address; pass --yes-i-own-this only if you own it or have permission to scan it");
                return ExitUsage;
            }
        }

        var config = new ScanConfig { Address = address, Timeout = options.Timeout, Banner = options.Banner };

        var stopwatch = Stopwatch.StartNew();
        var results = await Scanner.ScanPortsAsync(config, ports, options.Concurrency).ConfigureAwait(false);
        stopwatch.Stop();

        var report = new ScanReport
        {
            Target = options.Target,
            Address = address.ToString(),
            Results = results,
            ElapsedMs = stopwatch.ElapsedMilliseconds,
        };

        Console.Write(options.Format == ReportFormat.Json ? Report.WriteJson(report) : Report.WriteTable(report));
        return ExitOk;
    }

    private static async Task<IPAddress> ResolveAsync(string target)
    {
        if (IPAddress.TryParse(target, out var literal))
        {
            return literal;
        }
        var addresses = await Dns.GetHostAddressesAsync(target).ConfigureAwait(false);
        var chosen = addresses.FirstOrDefault(item => item.AddressFamily == AddressFamily.InterNetwork) ??
                     addresses.FirstOrDefault();
        return chosen ?? throw new SocketException((int)SocketError.HostNotFound);
    }
}
