#include "Args.hpp"

#include <charconv>
#include <format>

namespace portscan {
namespace {

constexpr unsigned kMinTimeoutMs = 50;
constexpr unsigned kMaxTimeoutMs = 60000;
constexpr unsigned kMinConcurrency = 1;
constexpr unsigned kMaxConcurrency = 10000;

std::expected<unsigned long long, std::string> toNumber(std::string_view text) {
    unsigned long long value{};
    const auto result = std::from_chars(text.data(), text.data() + text.size(), value);

    if (result.ec != std::errc{} || result.ptr != text.data() + text.size()) {
        return std::unexpected(std::format("a number was expected: {}", text));
    }
    return value;
}

bool isValueFlag(std::string_view arg) {
    return arg == "--ports" || arg == "--timeout" || arg == "--concurrency" || arg == "--format";
}

}

std::string_view usage() {
    return "portscan <target> [--ports 1-1024|22,80,443] [--timeout <ms>] [--concurrency <n>]\n"
           "                 [--banner] [--format table|json] [--yes-i-own-this] [--help]\n";
}

std::expected<Options, std::string> parseArgs(std::span<const std::string_view> args) {
    Options options;

    for (std::size_t i = 0; i < args.size(); ++i) {
        const std::string_view arg = args[i];

        if (arg == "--help" || arg == "-h") {
            options.help = true;
            return options;
        }
        if (arg == "--banner") {
            options.banner = true;
            continue;
        }
        if (arg == "--yes-i-own-this") {
            options.confirmed = true;
            continue;
        }
        if (isValueFlag(arg)) {
            if (i + 1 >= args.size()) {
                return std::unexpected(std::format("{} is missing a value", arg));
            }
            const std::string_view value = args[++i];

            if (arg == "--ports") {
                options.portsSpec = std::string(value);
            } else if (arg == "--format") {
                if (value == "table") {
                    options.format = ReportFormat::Table;
                } else if (value == "json") {
                    options.format = ReportFormat::Json;
                } else {
                    return std::unexpected("format must be table or json");
                }
            } else {
                auto number = toNumber(value);
                if (!number) {
                    return std::unexpected(number.error());
                }
                if (arg == "--timeout") {
                    if (*number < kMinTimeoutMs || *number > kMaxTimeoutMs) {
                        return std::unexpected("timeout must be between 50 and 60000 ms");
                    }
                    options.timeout = std::chrono::milliseconds{static_cast<long long>(*number)};
                } else {
                    if (*number < kMinConcurrency || *number > kMaxConcurrency) {
                        return std::unexpected("concurrency must be between 1 and 10000");
                    }
                    options.concurrency = static_cast<unsigned>(*number);
                }
            }
            continue;
        }
        if (arg.starts_with("--")) {
            return std::unexpected(std::format("unknown argument: {}", arg));
        }
        if (!options.target.empty()) {
            return std::unexpected("only one target is allowed");
        }
        options.target = std::string(arg);
    }

    if (options.target.empty()) {
        return std::unexpected("a target is required");
    }
    return options;
}

}
