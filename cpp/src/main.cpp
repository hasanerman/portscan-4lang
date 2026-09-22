#include <iostream>
#include <span>
#include <string_view>
#include <vector>

#include "Args.hpp"
#include "Ports.hpp"
#include "Report.hpp"
#include "Scanner.hpp"
#include "Socket.hpp"

namespace {

constexpr int kExitOk = 0;
constexpr int kExitUsage = 1;
constexpr int kExitUnresolved = 2;

bool scanAllowed(const portscan::Options& options, const portscan::Address& address) {
    if (portscan::isLocalAddress(address)) {
        return true;
    }
    if (options.confirmed) {
        std::cerr << "note: scanning a non-local target\n";
        return true;
    }
    std::cerr << "error: " << options.target
              << " is not a local or private address; pass --yes-i-own-this only if you own it or have permission "
                 "to scan it\n";
    return false;
}

int runScan(const portscan::Options& options, const std::vector<std::uint16_t>& ports, const portscan::Address& address,
            const std::string& text) {
    portscan::ScanConfig config;
    config.address = address;
    config.timeout = options.timeout;
    config.banner = options.banner;

    const auto start = portscan::steadyNow();
    auto results = portscan::scanPorts(config, ports, options.concurrency);
    const auto elapsedMs =
        static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(portscan::steadyNow() - start).count());

    portscan::ScanReport report;
    report.target = options.target;
    report.address = text;
    report.results = results;
    report.elapsedMs = elapsedMs;

    if (options.format == portscan::ReportFormat::Json) {
        portscan::writeJson(std::cout, report);
    } else {
        portscan::writeTable(std::cout, report);
    }
    return kExitOk;
}

int prepareAndScan(const portscan::Options& options) {
    auto ports = portscan::parsePorts(options.portsSpec);
    if (!ports) {
        std::cerr << "error: " << ports.error() << '\n';
        return kExitUsage;
    }

    auto address = portscan::resolve(options.target);
    if (!address) {
        std::cerr << "error: cannot resolve " << options.target << '\n';
        return kExitUnresolved;
    }
    const std::string text = portscan::formatAddress(*address);

    if (!scanAllowed(options, *address)) {
        return kExitUsage;
    }
    return runScan(options, *ports, *address, text);
}

}

int main(int argc, char** argv) {
    std::vector<std::string_view> raw;
    raw.reserve(static_cast<std::size_t>(argc > 0 ? argc - 1 : 0));
    for (int i = 1; i < argc; ++i) {
        raw.emplace_back(argv[i]);
    }

    const auto parsed = portscan::parseArgs(std::span<const std::string_view>{raw});
    if (!parsed) {
        std::cerr << "error: " << parsed.error() << '\n' << portscan::usage();
        return kExitUsage;
    }
    if (parsed->help) {
        std::cout << portscan::usage();
        return kExitOk;
    }

    if (!portscan::networkInit()) {
        std::cerr << "error: network initialisation failed\n";
        return kExitUnresolved;
    }
    const int code = prepareAndScan(*parsed);
    portscan::networkCleanup();
    return code;
}
