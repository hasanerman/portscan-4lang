#include "Ports.hpp"

#include <algorithm>
#include <charconv>
#include <format>
#include <set>

namespace portscan {
namespace {

std::expected<std::uint32_t, std::string> parseNumber(std::string_view text) {
    std::uint32_t value = 0;
    const auto result = std::from_chars(text.data(), text.data() + text.size(), value);

    if (result.ec != std::errc{} || result.ptr != text.data() + text.size()) {
        return std::unexpected(std::format("a number was expected: {}", text));
    }
    if (value < kPortMin || value > kPortMax) {
        return std::unexpected("port must be a number between 1 and 65535");
    }
    return value;
}

std::expected<void, std::string> markToken(std::string_view token, std::set<std::uint16_t>& marked) {
    const auto dash = token.find('-');

    if (dash == std::string_view::npos) {
        auto port = parseNumber(token);
        if (!port) {
            return std::unexpected(port.error());
        }
        marked.insert(static_cast<std::uint16_t>(*port));
        return {};
    }

    auto first = parseNumber(token.substr(0, dash));
    if (!first) {
        return std::unexpected(first.error());
    }
    auto last = parseNumber(token.substr(dash + 1));
    if (!last) {
        return std::unexpected(last.error());
    }
    if (*first > *last) {
        return std::unexpected("port range start is greater than its end");
    }
    for (auto port = *first; port <= *last; ++port) {
        marked.insert(static_cast<std::uint16_t>(port));
    }
    return {};
}

}

std::expected<std::vector<std::uint16_t>, std::string> parsePorts(std::string_view spec) {
    if (spec.empty()) {
        return std::unexpected("port list is empty");
    }

    std::set<std::uint16_t> marked;
    std::size_t start = 0;

    while (start <= spec.size()) {
        const auto comma = spec.find(',', start);
        const auto token = comma == std::string_view::npos ? spec.substr(start) : spec.substr(start, comma - start);

        if (auto result = markToken(token, marked); !result) {
            return std::unexpected(result.error());
        }
        if (comma == std::string_view::npos) {
            break;
        }
        start = comma + 1;
    }

    return std::vector<std::uint16_t>(marked.begin(), marked.end());
}

}
