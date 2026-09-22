#ifndef _WIN32

#include "Socket.hpp"

#include <array>
#include <cstring>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <time.h>
#include <unistd.h>

namespace portscan {
namespace {

bool isAllZero(const std::byte* bytes, std::size_t length) {
    for (std::size_t i = 0; i < length; ++i) {
        if (bytes[i] != std::byte{0}) {
            return false;
        }
    }
    return true;
}

bool isLocalV4(const std::byte* b) {
    const auto v = [b](std::size_t i) { return static_cast<unsigned>(b[i]); };
    return v(0) == 127 || v(0) == 10 || v(0) == 0 || (v(0) == 172 && v(1) >= 16 && v(1) <= 31) ||
           (v(0) == 192 && v(1) == 168) || (v(0) == 169 && v(1) == 254);
}

bool isLocalV6(const std::byte* b) {
    if (isAllZero(b, 15) && (b[15] == std::byte{0} || b[15] == std::byte{1})) {
        return true;
    }
    if (b[0] == std::byte{0xfe} && (static_cast<unsigned>(b[1]) & 0xc0) == 0x80) {
        return true;
    }
    if ((static_cast<unsigned>(b[0]) & 0xfe) == 0xfc) {
        return true;
    }
    if (isAllZero(b, 10) && b[10] == std::byte{0xff} && b[11] == std::byte{0xff}) {
        return isLocalV4(b + 12);
    }
    return false;
}

}

bool networkInit() {
    return true;
}

void networkCleanup() {
}

std::optional<Address> parseLiteral(const std::string& text) {
    sockaddr_in v4{};
    sockaddr_in6 v6{};

    if (inet_pton(AF_INET, text.c_str(), &v4.sin_addr) == 1) {
        v4.sin_family = AF_INET;
        Address address;
        std::memcpy(&address.storage, &v4, sizeof(v4));
        address.length = sizeof(v4);
        address.family = AF_INET;
        return address;
    }
    if (inet_pton(AF_INET6, text.c_str(), &v6.sin6_addr) == 1) {
        v6.sin6_family = AF_INET6;
        Address address;
        std::memcpy(&address.storage, &v6, sizeof(v6));
        address.length = sizeof(v6);
        address.family = AF_INET6;
        return address;
    }
    return std::nullopt;
}

std::optional<Address> resolve(const std::string& host) {
    addrinfo hints{};
    addrinfo* list = nullptr;

    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(host.c_str(), nullptr, &hints, &list) != 0 || list == nullptr) {
        return std::nullopt;
    }
    const addrinfo* chosen = list;
    for (const addrinfo* item = list; item != nullptr; item = item->ai_next) {
        if (item->ai_family == AF_INET) {
            chosen = item;
            break;
        }
    }
    if (static_cast<std::size_t>(chosen->ai_addrlen) > sizeof(sockaddr_storage)) {
        freeaddrinfo(list);
        return std::nullopt;
    }

    Address address;
    std::memcpy(&address.storage, chosen->ai_addr, static_cast<std::size_t>(chosen->ai_addrlen));
    address.length = static_cast<std::size_t>(chosen->ai_addrlen);
    address.family = chosen->ai_family;
    freeaddrinfo(list);
    return address;
}

std::string formatAddress(const Address& address) {
    std::array<char, 64> text{};

    if (address.family == AF_INET) {
        sockaddr_in v4{};
        std::memcpy(&v4, &address.storage, sizeof(v4));
        inet_ntop(AF_INET, &v4.sin_addr, text.data(), text.size());
    } else if (address.family == AF_INET6) {
        sockaddr_in6 v6{};
        std::memcpy(&v6, &address.storage, sizeof(v6));
        inet_ntop(AF_INET6, &v6.sin6_addr, text.data(), text.size());
    }
    return std::string(text.data());
}

void setPort(Address& address, std::uint16_t port) {
    if (address.family == AF_INET) {
        sockaddr_in v4{};
        std::memcpy(&v4, &address.storage, sizeof(v4));
        v4.sin_port = htons(port);
        std::memcpy(&address.storage, &v4, sizeof(v4));
    } else if (address.family == AF_INET6) {
        sockaddr_in6 v6{};
        std::memcpy(&v6, &address.storage, sizeof(v6));
        v6.sin6_port = htons(port);
        std::memcpy(&address.storage, &v6, sizeof(v6));
    }
}

bool isLocalAddress(const Address& address) {
    if (address.family == AF_INET) {
        sockaddr_in v4{};
        std::memcpy(&v4, &address.storage, sizeof(v4));
        return isLocalV4(reinterpret_cast<const std::byte*>(&v4.sin_addr));
    }
    if (address.family == AF_INET6) {
        sockaddr_in6 v6{};
        std::memcpy(&v6, &address.storage, sizeof(v6));
        return isLocalV6(reinterpret_cast<const std::byte*>(&v6.sin6_addr));
    }
    return false;
}

void UniqueSocket::reset() noexcept {
    if (valid()) {
        close(handle_);
    }
    handle_ = kInvalidSocket;
}

UniqueSocket openSocket(const Address& address) {
    SocketHandle raw = socket(address.family, SOCK_STREAM, 0);

    if (raw == kInvalidSocket) {
        return UniqueSocket{};
    }
    const int flags = fcntl(raw, F_GETFL, 0);
    if (flags < 0 || fcntl(raw, F_SETFL, flags | O_NONBLOCK) != 0) {
        close(raw);
        return UniqueSocket{};
    }
    return UniqueSocket{raw};
}

ConnectResult connectSocket(const UniqueSocket& socket, const Address& address, int& error) {
    const int status =
        ::connect(socket.get(), reinterpret_cast<const sockaddr*>(&address.storage), static_cast<socklen_t>(address.length));

    error = 0;
    if (status == 0) {
        return ConnectResult::Done;
    }
    error = errno;
    return (error == EINPROGRESS || error == EINTR) ? ConnectResult::Pending : ConnectResult::Failed;
}

WaitOutcome waitSocket(const UniqueSocket& socket, bool forWrite, std::chrono::milliseconds timeout) {
    pollfd item{};
    int status;

    item.fd = socket.get();
    item.events = forWrite ? POLLOUT : POLLIN;
    do {
        status = poll(&item, 1, static_cast<int>(timeout.count()));
    } while (status < 0 && errno == EINTR);
    if (status == 0) {
        return WaitOutcome::Timeout;
    }
    return status < 0 ? WaitOutcome::Failed : WaitOutcome::Ready;
}

int socketError(const UniqueSocket& socket) {
    int value = 0;
    socklen_t length = sizeof(value);

    if (getsockopt(socket.get(), SOL_SOCKET, SO_ERROR, &value, &length) != 0) {
        return errno;
    }
    return value;
}

PortOutcome classifyError(int error) {
    if (error == ECONNREFUSED) {
        return PortOutcome::Closed;
    }
    if (error == ETIMEDOUT || error == EHOSTUNREACH || error == ENETUNREACH || error == EHOSTDOWN ||
        error == EACCES || error == EPERM) {
        return PortOutcome::Filtered;
    }
    return PortOutcome::Unknown;
}

long sendAll(const UniqueSocket& socket, std::string_view data) {
    return send(socket.get(), data.data(), data.size(), MSG_NOSIGNAL);
}

long receiveSome(const UniqueSocket& socket, std::span<std::byte> buffer) {
    return recv(socket.get(), buffer.data(), buffer.size(), 0);
}

std::chrono::steady_clock::time_point steadyNow() {
    return std::chrono::steady_clock::now();
}

}

#endif
