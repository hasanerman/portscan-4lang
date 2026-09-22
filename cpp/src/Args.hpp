#pragma once

#include <chrono>
#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <string_view>

namespace portscan {

enum class ReportFormat { Table, Json };

struct Options {
    std::string target;
    std::string portsSpec{"1-1024"};
    std::chrono::milliseconds timeout{800};
    unsigned concurrency{500};
    bool banner{false};
    ReportFormat format{ReportFormat::Table};
    bool confirmed{false};
    bool help{false};
};

std::expected<Options, std::string> parseArgs(std::span<const std::string_view> args);
std::string_view usage();

}
