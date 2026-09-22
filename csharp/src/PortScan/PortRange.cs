using System.Globalization;

namespace PortScan;

public sealed class PortListParseException : Exception
{
    public PortListParseException(string message)
        : base(message)
    {
    }

    public PortListParseException()
    {
    }

    public PortListParseException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}

public static class PortRange
{
    public const int PortMin = 1;
    public const int PortMax = 65535;

    public static IReadOnlyList<ushort> Parse(string spec)
    {
        ArgumentNullException.ThrowIfNull(spec);

        if (spec.Length == 0)
        {
            throw new PortListParseException("port list is empty");
        }

        var marked = new SortedSet<ushort>();
        foreach (var token in spec.Split(','))
        {
            MarkToken(token, marked);
        }
        return marked.ToList();
    }

    private static void MarkToken(string token, SortedSet<ushort> marked)
    {
        var dash = token.IndexOf('-', StringComparison.Ordinal);

        if (dash < 0)
        {
            marked.Add((ushort)ParseNumber(token));
            return;
        }

        var first = ParseNumber(token[..dash]);
        var last = ParseNumber(token[(dash + 1)..]);
        if (first > last)
        {
            throw new PortListParseException("port range start is greater than its end");
        }
        for (var port = first; port <= last; port++)
        {
            marked.Add((ushort)port);
        }
    }

    private static int ParseNumber(string text)
    {
        if (!int.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out var value) ||
            value < PortMin || value > PortMax)
        {
            throw new PortListParseException($"port must be a number between 1 and 65535: {text}");
        }
        return value;
    }
}
