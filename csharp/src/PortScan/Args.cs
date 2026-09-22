namespace PortScan;

public enum ReportFormat
{
    Table,
    Json,
}

public sealed record Options
{
    public const int DefaultTimeoutMs = 800;
    public const int MinTimeoutMs = 50;
    public const int MaxTimeoutMs = 60_000;
    public const int DefaultConcurrency = 500;
    public const int MinConcurrency = 1;
    public const int MaxConcurrency = 10_000;

    public string Target { get; init; } = string.Empty;

    public string PortsSpec { get; init; } = "1-1024";

    public TimeSpan Timeout { get; init; } = TimeSpan.FromMilliseconds(DefaultTimeoutMs);

    public int Concurrency { get; init; } = DefaultConcurrency;

    public bool Banner { get; init; }

    public ReportFormat Format { get; init; } = ReportFormat.Table;

    public bool Confirmed { get; init; }

    public bool Help { get; init; }
}

public sealed class ArgumentParseException : Exception
{
    public ArgumentParseException(string message)
        : base(message)
    {
    }

    public ArgumentParseException()
    {
    }

    public ArgumentParseException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}

public static class Args
{
    public static string Usage =>
        "portscan <target> [--ports 1-1024|22,80,443] [--timeout <ms>] [--concurrency <n>]" + Environment.NewLine +
        "                 [--banner] [--format table|json] [--yes-i-own-this] [--help]" + Environment.NewLine;

    private static readonly HashSet<string> ValueFlags = ["--ports", "--timeout", "--concurrency", "--format"];

    public static Options Parse(IReadOnlyList<string> arguments)
    {
        ArgumentNullException.ThrowIfNull(arguments);

        var options = new Options();

        for (var index = 0; index < arguments.Count; index++)
        {
            var argument = arguments[index];

            if (argument is "--help" or "-h")
            {
                return options with { Help = true };
            }
            if (argument == "--banner")
            {
                options = options with { Banner = true };
                continue;
            }
            if (argument == "--yes-i-own-this")
            {
                options = options with { Confirmed = true };
                continue;
            }
            if (ValueFlags.Contains(argument))
            {
                if (index + 1 >= arguments.Count)
                {
                    throw new ArgumentParseException($"{argument} is missing a value");
                }
                options = ApplyValue(argument, arguments[++index], options);
                continue;
            }
            if (argument.StartsWith("--", StringComparison.Ordinal))
            {
                throw new ArgumentParseException($"unknown argument: {argument}");
            }
            if (options.Target.Length != 0)
            {
                throw new ArgumentParseException("only one target is allowed");
            }
            options = options with { Target = argument };
        }

        if (options.Target.Length == 0)
        {
            throw new ArgumentParseException("a target is required");
        }
        return options;
    }

    private static Options ApplyValue(string flag, string value, Options options) => flag switch
    {
        "--ports" => options with { PortsSpec = value },
        "--format" => options with { Format = ParseFormat(value) },
        "--timeout" => options with { Timeout = TimeSpan.FromMilliseconds(ParseBoundedNumber(value, Options.MinTimeoutMs, Options.MaxTimeoutMs, "timeout must be between 50 and 60000 ms")) },
        _ => options with { Concurrency = ParseBoundedNumber(value, Options.MinConcurrency, Options.MaxConcurrency, "concurrency must be between 1 and 10000") },
    };

    private static ReportFormat ParseFormat(string value) => value switch
    {
        "table" => ReportFormat.Table,
        "json" => ReportFormat.Json,
        _ => throw new ArgumentParseException("format must be table or json"),
    };

    private static int ParseBoundedNumber(string value, int minimum, int maximum, string errorMessage)
    {
        if (!long.TryParse(value, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var number) ||
            number < minimum || number > maximum)
        {
            throw new ArgumentParseException(errorMessage);
        }
        return (int)number;
    }
}
