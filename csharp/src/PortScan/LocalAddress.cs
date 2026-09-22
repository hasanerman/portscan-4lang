using System.Net;
using System.Net.Sockets;

namespace PortScan;

public static class LocalAddress
{
    public static bool IsLocal(IPAddress address)
    {
        ArgumentNullException.ThrowIfNull(address);

        if (address.IsIPv4MappedToIPv6)
        {
            return IsLocalV4(address.MapToIPv4().GetAddressBytes());
        }
        return address.AddressFamily switch
        {
            AddressFamily.InterNetwork => IsLocalV4(address.GetAddressBytes()),
            AddressFamily.InterNetworkV6 => IsLocalV6(address.GetAddressBytes()),
            _ => false,
        };
    }

    private static bool IsLocalV4(byte[] b) =>
        b[0] == 127 || b[0] == 10 || b[0] == 0 ||
        (b[0] == 172 && b[1] is >= 16 and <= 31) ||
        (b[0] == 192 && b[1] == 168) ||
        (b[0] == 169 && b[1] == 254);

    private static bool IsLocalV6(byte[] b)
    {
        if (b[..15].All(value => value == 0) && b[15] is 0 or 1)
        {
            return true;
        }
        if (b[0] == 0xfe && (b[1] & 0xc0) == 0x80)
        {
            return true;
        }
        return (b[0] & 0xfe) == 0xfc;
    }
}
