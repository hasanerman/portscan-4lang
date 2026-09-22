#include "../src/Report.hpp"
#include "../src/Scanner.hpp"
#include "../src/Socket.hpp"

#include <array>
#include <iostream>
#include <sstream>
#include <string_view>
#include <thread>
#include <vector>

#ifdef _WIN32
using addr_len_t = int;
#else
#include <unistd.h>
using addr_len_t = socklen_t;
#endif

namespace {

int g_failures = 0;

void check(bool condition, std::string_view label, int line) {
    if (!condition) {
        std::cout << "FAIL line " << line << ": " << label << '\n';
        ++g_failures;
    }
}

#define CHECK(expr) check((expr), #expr, __LINE__)

bool isLocalText(const std::string& text) {
    auto address = portscan::parseLiteral(text);
    return address.has_value() && portscan::isLocalAddress(*address);
}

void testLocalAddressDetection() {
    CHECK(isLocalText("127.0.0.1"));
    CHECK(isLocalText("10.1.2.3"));
    CHECK(isLocalText("172.16.0.1"));
    CHECK(isLocalText("172.31.255.255"));
    CHECK(isLocalText("192.168.1.1"));
    CHECK(isLocalText("169.254.1.1"));
    CHECK(isLocalText("0.0.0.0"));
    CHECK(isLocalText("::1"));
    CHECK(isLocalText("fe80::1"));
    CHECK(isLocalText("fd00::1"));
    CHECK(isLocalText("::ffff:10.0.0.1"));
    CHECK(!isLocalText("8.8.8.8"));
    CHECK(!isLocalText("1.1.1.1"));
    CHECK(!isLocalText("172.32.0.1"));
    CHECK(!isLocalText("172.15.0.1"));
    CHECK(!isLocalText("192.169.0.1"));
    CHECK(!isLocalText("2001:4860:4860::8888"));
    CHECK(!isLocalText("::ffff:8.8.8.8"));
    CHECK(!portscan::parseLiteral("not-an-ip").has_value());
    CHECK(!portscan::parseLiteral("999.1.1.1").has_value());
}

void testSanitizeBanner() {
    const std::string ssh = "SSH-2.0-OpenSSH_9.6\r\nextra";
    const std::array<std::byte, 5> binary{std::byte{'A'}, std::byte{0x01}, std::byte{'B'}, std::byte{0xff},
                                          std::byte{'C'}};
    const std::string padded = "\r\n  220 hello  \r\n";
    std::vector<std::byte> longer(300, std::byte{'x'});

    auto toBytes = [](const std::string& text) {
        return std::span<const std::byte>(reinterpret_cast<const std::byte*>(text.data()), text.size());
    };

    CHECK(portscan::sanitizeBanner(toBytes(ssh)) == "SSH-2.0-OpenSSH_9.6");
    CHECK(portscan::sanitizeBanner(binary) == "A.B.C");
    CHECK(portscan::sanitizeBanner(toBytes(padded)) == "220 hello");
    CHECK(portscan::sanitizeBanner(longer).size() == portscan::kBannerMaxChars);
    CHECK(portscan::sanitizeBanner({}).empty());
}

void testHttpPorts() {
    CHECK(portscan::isHttpPort(80) && portscan::isHttpPort(8080) && portscan::isHttpPort(8000) &&
          portscan::isHttpPort(8888));
    CHECK(!portscan::isHttpPort(22) && !portscan::isHttpPort(443));
}

portscan::UniqueSocket openListener(std::uint16_t& port) {
    auto address = portscan::parseLiteral("127.0.0.1");
    portscan::setPort(*address, 0);

    SocketHandle handle = socket(address->family, SOCK_STREAM, 0);
    if (handle == kInvalidSocket) {
        return portscan::UniqueSocket{};
    }
    if (::bind(handle, reinterpret_cast<const sockaddr*>(&address->storage), static_cast<addr_len_t>(address->length)) !=
            0 ||
        ::listen(handle, 512) != 0) {
#ifdef _WIN32
        closesocket(handle);
#else
        close(handle);
#endif
        return portscan::UniqueSocket{};
    }
    sockaddr_in bound{};
    addr_len_t length = sizeof(bound);
    getsockname(handle, reinterpret_cast<sockaddr*>(&bound), &length);
    port = ntohs(bound.sin_port);
    return portscan::UniqueSocket{handle};
}

portscan::ScanConfig makeConfig(bool banner) {
    portscan::ScanConfig config;
    config.address = *portscan::parseLiteral("127.0.0.1");
    config.timeout = std::chrono::milliseconds{2000};
    config.banner = banner;
    return config;
}

void testOpenAndClosedPorts() {
    std::uint16_t port = 0;
    auto listener = openListener(port);
    CHECK(listener.valid());

    auto config = makeConfig(false);
    auto openResult = portscan::scanPort(config, port);
    CHECK(openResult.state == portscan::PortState::Open);

    listener = portscan::UniqueSocket{};
    auto closedResult = portscan::scanPort(config, port);
    CHECK(closedResult.state == portscan::PortState::Closed);
}

void serveBanner(const portscan::UniqueSocket& listener) {
    static constexpr std::string_view text = "220 izci test ready\r\n";

    if (portscan::waitSocket(listener, false, std::chrono::milliseconds{3000}) != portscan::WaitOutcome::Ready) {
        return;
    }
    SocketHandle client = accept(listener.get(), nullptr, nullptr);
    if (client == kInvalidSocket) {
        return;
    }
    portscan::UniqueSocket owned{client};
    portscan::sendAll(owned, text);
    portscan::waitSocket(owned, false, std::chrono::milliseconds{1000});
}

void testBannerGrab() {
    std::uint16_t port = 0;
    auto listener = openListener(port);
    CHECK(listener.valid());

    auto config = makeConfig(true);
    portscan::PortResult result;
    std::jthread server([&] { serveBanner(listener); });
    std::jthread client([&] { result = portscan::scanPort(config, port); });
    server.join();
    client.join();

    CHECK(result.state == portscan::PortState::Open);
    CHECK(result.banner == "220 izci test ready");
}

void testRepeatedScansAreStable() {
    constexpr int kRangeSize = 200;
    constexpr int kRounds = 20;

    std::uint16_t port = 0;
    auto listener = openListener(port);
    CHECK(listener.valid());

    const auto config = makeConfig(false);
    const auto first = static_cast<std::uint16_t>(port - kRangeSize / 2);
    std::vector<std::uint16_t> ports(kRangeSize);
    for (int i = 0; i < kRangeSize; ++i) {
        ports[static_cast<std::size_t>(i)] = static_cast<std::uint16_t>(first + i);
    }

    const auto listenerIndex = static_cast<std::size_t>(port - first);

    // Only the port this test owns is asserted on. The rest of the window sits
    // in the OS ephemeral range, where unrelated processes claim and release
    // ports while the scan runs. Repetition proves that our scanner keeps
    // returning a complete, correctly ordered result set and never loses the
    // one port we control, which is what a socket leak would break.
    for (int round = 0; round <= kRounds; ++round) {
        auto current = portscan::scanPorts(config, ports, 64);

        CHECK(current.size() == ports.size());
        bool ordered = true;
        for (std::size_t i = 0; i < current.size(); ++i) {
            if (current[i].port != ports[i]) {
                ordered = false;
                break;
            }
        }
        CHECK(ordered);
        CHECK(current[listenerIndex].state == portscan::PortState::Open);
    }
}

}

int main() {
    if (!portscan::networkInit()) {
        std::cout << "test_scan: network initialisation failed\n";
        return 1;
    }
    testLocalAddressDetection();
    testSanitizeBanner();
    testHttpPorts();
    testOpenAndClosedPorts();
    testBannerGrab();
    testRepeatedScansAreStable();
    portscan::networkCleanup();

    if (g_failures == 0) {
        std::cout << "test_scan: all tests passed\n";
        return 0;
    }
    std::cout << "test_scan: " << g_failures << " checks failed\n";
    return 1;
}
