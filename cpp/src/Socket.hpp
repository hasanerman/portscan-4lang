#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
using SocketHandle = SOCKET;
constexpr SocketHandle kInvalidSocket = INVALID_SOCKET;
#else
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
using SocketHandle = int;
constexpr SocketHandle kInvalidSocket = -1;
#endif

namespace portscan {

struct Address {
    sockaddr_storage storage{};
    std::size_t length{};
    int family{};
};

enum class ConnectResult { Done, Pending, Failed };
enum class WaitOutcome { Ready, Timeout, Failed };
enum class PortOutcome { Closed, Filtered, Unknown };

bool networkInit();
void networkCleanup();

std::optional<Address> parseLiteral(const std::string& text);
std::optional<Address> resolve(const std::string& host);
std::string formatAddress(const Address& address);
void setPort(Address& address, std::uint16_t port);
bool isLocalAddress(const Address& address);

class UniqueSocket {
public:
    UniqueSocket() = default;
    explicit UniqueSocket(SocketHandle handle) : handle_(handle) {}

    UniqueSocket(const UniqueSocket&) = delete;
    UniqueSocket& operator=(const UniqueSocket&) = delete;

    UniqueSocket(UniqueSocket&& other) noexcept : handle_(std::exchange(other.handle_, kInvalidSocket)) {}

    UniqueSocket& operator=(UniqueSocket&& other) noexcept {
        if (this != &other) {
            reset();
            handle_ = std::exchange(other.handle_, kInvalidSocket);
        }
        return *this;
    }

    ~UniqueSocket() { reset(); }

    [[nodiscard]] SocketHandle get() const noexcept { return handle_; }
    [[nodiscard]] bool valid() const noexcept { return handle_ != kInvalidSocket; }

private:
    void reset() noexcept;

    SocketHandle handle_{kInvalidSocket};
};

UniqueSocket openSocket(const Address& address);
ConnectResult connectSocket(const UniqueSocket& socket, const Address& address, int& error);
WaitOutcome waitSocket(const UniqueSocket& socket, bool forWrite, std::chrono::milliseconds timeout);
int socketError(const UniqueSocket& socket);
PortOutcome classifyError(int error);
long sendAll(const UniqueSocket& socket, std::string_view data);
long receiveSome(const UniqueSocket& socket, std::span<std::byte> buffer);

std::chrono::steady_clock::time_point steadyNow();

}
