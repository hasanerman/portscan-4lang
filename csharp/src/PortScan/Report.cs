using System.Globalization;
using System.Text;

namespace PortScan;

public sealed record ScanCounts
{
    public int Open { get; init; }

    public int Closed { get; init; }

    public int Filtered { get; init; }

    public int Errors { get; init; }
}

public sealed record ScanReport
{
    public required string Target { get; init; }

    public required string Address { get; init; }

    public required IReadOnlyList<PortResult> Results { get; init; }

    public required long ElapsedMs { get; init; }
}

public static class Report
{
    private const int TableWidth = 56;

    public static ScanCounts CountResults(IReadOnlyList<PortResult> results)
    {
        ArgumentNullException.ThrowIfNull(results);

        var open = 0;
        var closed = 0;
        var filtered = 0;
        var errors = 0;

        foreach (var item in results)
        {
            switch (item.State)
            {
                case PortState.Open:
                    open++;
                    break;
                case PortState.Closed:
                    closed++;
                    break;
                case PortState.Filtered:
                    filtered++;
                    break;
                case PortState.Error:
                    errors++;
                    break;
            }
        }

        return new ScanCounts { Open = open, Closed = closed, Filtered = filtered, Errors = errors };
    }

    public static string WriteTable(ScanReport report)
    {
        ArgumentNullException.ThrowIfNull(report);

        var counts = CountResults(report.Results);
        var builder = new StringBuilder();

        builder.Append(CultureInfo.InvariantCulture, $"{"PORT",-7} {"STATE",-9} {"MS",6}  BANNER");
        builder.Append('\n');
        builder.Append(new string('-', TableWidth));
        builder.Append('\n');

        foreach (var item in report.Results)
        {
            if (item.State == PortState.Open)
            {
                builder.Append(CultureInfo.InvariantCulture, $"{item.Port,-7} {item.State.Name(),-9} {item.Ms,6}  {item.Banner}");
                builder.Append('\n');
            }
        }

        builder.Append(CultureInfo.InvariantCulture,
            $"\nscanned {report.Results.Count} ports on {report.Target} ({report.Address}) in {report.ElapsedMs} ms: {counts.Open} open, {counts.Closed} closed, {counts.Filtered} filtered");
        if (counts.Errors > 0)
        {
            builder.Append(CultureInfo.InvariantCulture, $", {counts.Errors} errors");
        }
        builder.Append('\n');

        return builder.ToString();
    }

    public static void WriteJsonString(StringBuilder builder, string text)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(text);

        builder.Append('"');
        foreach (var ch in text)
        {
            var value = (byte)ch;
            if (ch == '"' || ch == '\\')
            {
                builder.Append('\\').Append(ch);
            }
            else if (value < 0x20)
            {
                builder.Append(CultureInfo.InvariantCulture, $"\\u{value:x4}");
            }
            else
            {
                builder.Append(ch);
            }
        }
        builder.Append('"');
    }

    public static string WriteJson(ScanReport report)
    {
        ArgumentNullException.ThrowIfNull(report);

        var counts = CountResults(report.Results);
        var builder = new StringBuilder();

        builder.Append("{\"target\":");
        WriteJsonString(builder, report.Target);
        builder.Append(",\"address\":");
        WriteJsonString(builder, report.Address);
        builder.Append(CultureInfo.InvariantCulture, $",\"scanned\":{report.Results.Count},\"open\":[");

        var first = true;
        foreach (var item in report.Results)
        {
            if (item.State != PortState.Open)
            {
                continue;
            }
            if (!first)
            {
                builder.Append(',');
            }
            builder.Append(CultureInfo.InvariantCulture, $"{{\"port\":{item.Port},\"state\":\"{item.State.Name()}\",\"banner\":");
            WriteJsonString(builder, item.Banner);
            builder.Append(CultureInfo.InvariantCulture, $",\"ms\":{item.Ms}}}");
            first = false;
        }

        builder.Append(CultureInfo.InvariantCulture,
            $"],\"closed\":{counts.Closed},\"filtered\":{counts.Filtered},\"errors\":{counts.Errors},\"elapsed_ms\":{report.ElapsedMs}}}");
        builder.Append('\n');
        return builder.ToString();
    }
}
