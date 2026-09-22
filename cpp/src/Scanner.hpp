#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "Socket.hpp"

namespace portscan {

constexpr std::size_t kBannerMaxChars = 120;

enum class PortState { Open, Closed, Filtered, Error };

struct PortResult {
    std::uint16_t port{};
    PortState state{PortState::Error};
    unsigned ms{};
    std::string banner;
};

struct ScanConfig {
    Address address;
    std::chrono::milliseconds timeout{800};
    bool banner{false};
};

std::string_view portStateName(PortState state);
bool isHttpPort(std::uint16_t port);
std::string sanitizeBanner(std::span<const std::byte> data);
PortResult scanPort(const ScanConfig& config, std::uint16_t port);
std::vector<PortResult> scanPorts(const ScanConfig& config, std::span<const std::uint16_t> ports, unsigned concurrency);

}
