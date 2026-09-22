#include "Report.hpp"

#include <format>
#include <iomanip>

namespace portscan {
namespace {

constexpr int kTableWidth = 56;

}

ScanCounts countResults(std::span<const PortResult> results) {
    ScanCounts counts;

    for (const auto& item : results) {
        switch (item.state) {
        case PortState::Open:
            ++counts.open;
            break;
        case PortState::Closed:
            ++counts.closed;
            break;
        case PortState::Filtered:
            ++counts.filtered;
            break;
        case PortState::Error:
            ++counts.errors;
            break;
        }
    }
    return counts;
}

void writeTable(std::ostream& out, const ScanReport& report) {
    const auto counts = countResults(report.results);

    out << std::format("{:<7} {:<9} {:>6}  {}\n", "PORT", "STATE", "MS", "BANNER");
    out << std::string(kTableWidth, '-') << '\n';
    for (const auto& item : report.results) {
        if (item.state == PortState::Open) {
            out << std::format("{:<7} {:<9} {:>6}  {}\n", item.port, portStateName(item.state), item.ms, item.banner);
        }
    }
    out << std::format("\nscanned {} ports on {} ({}) in {} ms: {} open, {} closed, {} filtered", report.results.size(),
                       report.target, report.address, report.elapsedMs, counts.open, counts.closed, counts.filtered);
    if (counts.errors > 0) {
        out << std::format(", {} errors", counts.errors);
    }
    out << '\n';
}

void writeJsonString(std::ostream& out, std::string_view text) {
    out << '"';
    for (const unsigned char value : text) {
        if (value == '"' || value == '\\') {
            out << '\\' << static_cast<char>(value);
        } else if (value < 0x20) {
            out << std::format("\\u{:04x}", value);
        } else {
            out << static_cast<char>(value);
        }
    }
    out << '"';
}

void writeJson(std::ostream& out, const ScanReport& report) {
    const auto counts = countResults(report.results);

    out << "{\"target\":";
    writeJsonString(out, report.target);
    out << ",\"address\":";
    writeJsonString(out, report.address);
    out << std::format(",\"scanned\":{},\"open\":[", report.results.size());

    bool first = true;
    for (const auto& item : report.results) {
        if (item.state != PortState::Open) {
            continue;
        }
        if (!first) {
            out << ',';
        }
        out << std::format("{{\"port\":{},\"state\":\"{}\",\"banner\":", item.port, portStateName(item.state));
        writeJsonString(out, item.banner);
        out << std::format(",\"ms\":{}}}", item.ms);
        first = false;
    }

    out << std::format("],\"closed\":{},\"filtered\":{},\"errors\":{},\"elapsed_ms\":{}}}\n", counts.closed,
                       counts.filtered, counts.errors, report.elapsedMs);
}

}
