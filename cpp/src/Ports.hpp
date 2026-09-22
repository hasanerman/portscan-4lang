#pragma once

#include <cstdint>
#include <expected>
#include <string>
#include <vector>

namespace portscan {

constexpr std::uint32_t kPortMin = 1;
constexpr std::uint32_t kPortMax = 65535;

std::expected<std::vector<std::uint16_t>, std::string> parsePorts(std::string_view spec);

}
