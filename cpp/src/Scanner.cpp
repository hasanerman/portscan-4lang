#include "Scanner.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <thread>

namespace portscan {
namespace {

constexpr std::string_view kHttpProbe = "HEAD / HTTP/1.0\r\n\r\n";
constexpr auto kBannerWait = std::chrono::milliseconds{500};
constexpr unsigned char kPrintableFirst = 0x20;
constexpr unsigned char kPrintableLast = 0x7e;

unsigned elapsedMs(std::chrono::steady_clock::time_point start) {
    return static_cast<unsigned>(
        std::chrono::duration_cast<std::chrono::milliseconds>(steadyNow() - start).count());
}

PortState stateFor(PortOutcome outcome) {
    if (outcome == PortOutcome::Closed) {
        return PortState::Closed;
    }
    return outcome == PortOutcome::Filtered ? PortState::Filtered : PortState::Error;
}

PortState connectPort(const Address& address, std::chrono::milliseconds timeout, UniqueSocket& out) {
    UniqueSocket socket = openSocket(address);
    int error = 0;

    if (!socket.valid()) {
        return PortState::Error;
    }
    switch (connectSocket(socket, address, error)) {
    case ConnectResult::Done:
        out = std::move(socket);
        return PortState::Open;
    case ConnectResult::Pending: {
        const auto waited = waitSocket(socket, true, timeout);
        if (waited == WaitOutcome::Timeout) {
            return PortState::Filtered;
        }
        error = waited == WaitOutcome::Ready ? socketError(socket) : -1;
        if (error == 0) {
            out = std::move(socket);
            return PortState::Open;
        }
        break;
    }
    case ConnectResult::Failed:
        break;
    }
    return stateFor(classifyError(error));
}

std::string readBanner(const UniqueSocket& socket, std::uint16_t port, std::chrono::milliseconds timeout) {
    std::array<std::byte, 1024> buffer{};
    const auto wait = std::min(timeout, kBannerWait);

    if (isHttpPort(port) && sendAll(socket, kHttpProbe) < 0) {
        return {};
    }
    if (waitSocket(socket, false, wait) != WaitOutcome::Ready) {
        return {};
    }
    const long received = receiveSome(socket, buffer);
    if (received <= 0) {
        return {};
    }
    return sanitizeBanner(std::span<const std::byte>(buffer.data(), static_cast<std::size_t>(received)));
}

}

std::string_view portStateName(PortState state) {
    switch (state) {
    case PortState::Open:
        return "open";
    case PortState::Closed:
        return "closed";
    case PortState::Filtered:
        return "filtered";
    case PortState::Error:
        return "error";
    }
    return "error";
}

bool isHttpPort(std::uint16_t port) {
    return port == 80 || port == 8000 || port == 8080 || port == 8888;
}

std::string sanitizeBanner(std::span<const std::byte> data) {
    std::string out;
    std::size_t i = 0;

    while (i < data.size()) {
        const auto value = static_cast<unsigned char>(data[i]);
        if (value != '\r' && value != '\n' && value != ' ') {
            break;
        }
        ++i;
    }
    for (; i < data.size() && out.size() < kBannerMaxChars; ++i) {
        const auto value = static_cast<unsigned char>(data[i]);
        if (value == '\r' || value == '\n') {
            break;
        }
        out.push_back((value >= kPrintableFirst && value <= kPrintableLast) ? static_cast<char>(value) : '.');
    }
    while (!out.empty() && out.back() == ' ') {
        out.pop_back();
    }
    return out;
}

PortResult scanPort(const ScanConfig& config, std::uint16_t port) {
    PortResult result;
    Address target = config.address;
    UniqueSocket socket;
    const auto start = steadyNow();

    result.port = port;
    setPort(target, port);
    result.state = connectPort(target, config.timeout, socket);
    result.ms = elapsedMs(start);
    if (!socket.valid()) {
        return result;
    }
    if (config.banner) {
        result.banner = readBanner(socket, port, config.timeout);
    }
    return result;
}

std::vector<PortResult> scanPorts(const ScanConfig& config, std::span<const std::uint16_t> ports, unsigned concurrency) {
    std::vector<PortResult> results(ports.size());
    std::atomic<std::size_t> nextIndex{0};
    const unsigned workers = std::min<unsigned>(concurrency, static_cast<unsigned>(ports.size()));

    auto worker = [&]() {
        for (;;) {
            const std::size_t index = nextIndex.fetch_add(1, std::memory_order_relaxed);
            if (index >= ports.size()) {
                return;
            }
            results[index] = scanPort(config, ports[index]);
        }
    };

    if (workers <= 1) {
        worker();
        return results;
    }

    std::vector<std::jthread> threads;
    threads.reserve(workers);
    for (unsigned i = 0; i < workers; ++i) {
        threads.emplace_back(worker);
    }
    return results;
}

}
