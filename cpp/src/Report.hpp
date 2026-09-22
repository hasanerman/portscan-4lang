#pragma once

#include <cstdint>
#include <ostream>
#include <span>
#include <string>

#include "Scanner.hpp"

namespace portscan {

struct ScanCounts {
    std::size_t open{};
    std::size_t closed{};
    std::size_t filtered{};
    std::size_t errors{};
};

struct ScanReport {
    std::string target;
    std::string address;
    std::span<const PortResult> results;
    std::uint64_t elapsedMs{};
};

ScanCounts countResults(std::span<const PortResult> results);
void writeTable(std::ostream& out, const ScanReport& report);
void writeJson(std::ostream& out, const ScanReport& report);
void writeJsonString(std::ostream& out, std::string_view text);

}
