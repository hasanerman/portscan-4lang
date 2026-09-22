#include "../src/Report.hpp"

#include <iostream>
#include <sstream>
#include <vector>

namespace {

int g_failures = 0;

void check(bool condition, std::string_view label, int line) {
    if (!condition) {
        std::cout << "FAIL line " << line << ": " << label << '\n';
        ++g_failures;
    }
}

#define CHECK(expr) check((expr), #expr, __LINE__)

portscan::PortResult make(std::uint16_t port, portscan::PortState state, unsigned ms, std::string banner) {
    portscan::PortResult item;
    item.port = port;
    item.state = state;
    item.ms = ms;
    item.banner = std::move(banner);
    return item;
}

void testCounts() {
    std::vector<portscan::PortResult> items{
        make(22, portscan::PortState::Open, 1, ""),
        make(23, portscan::PortState::Closed, 0, ""),
        make(24, portscan::PortState::Closed, 0, ""),
        make(25, portscan::PortState::Filtered, 800, ""),
        make(26, portscan::PortState::Error, 0, ""),
    };
    const auto counts = portscan::countResults(items);

    CHECK(counts.open == 1 && counts.closed == 2 && counts.filtered == 1 && counts.errors == 1);
}

void testJsonLayout() {
    std::vector<portscan::PortResult> items{
        make(22, portscan::PortState::Open, 2, "SSH-2.0-test"),
        make(23, portscan::PortState::Closed, 0, ""),
        make(24, portscan::PortState::Filtered, 800, ""),
    };
    portscan::ScanReport report{"host", "127.0.0.1", items, 9};

    std::ostringstream out;
    portscan::writeJson(out, report);

    CHECK(out.str() ==
         "{\"target\":\"host\",\"address\":\"127.0.0.1\",\"scanned\":3,\"open\":[{\"port\":22,\"state\":"
         "\"open\",\"banner\":\"SSH-2.0-test\",\"ms\":2}],\"closed\":1,\"filtered\":1,\"errors\":0,"
         "\"elapsed_ms\":9}\n");
}

void testJsonEscapesBanner() {
    std::vector<portscan::PortResult> items{make(80, portscan::PortState::Open, 1, "say \"hi\" \\ done")};
    portscan::ScanReport report{"t", "127.0.0.1", items, 1};

    std::ostringstream out;
    portscan::writeJson(out, report);

    CHECK(out.str().find("\"banner\":\"say \\\"hi\\\" \\\\ done\"") != std::string::npos);
}

void testTableListsOnlyOpenPorts() {
    std::vector<portscan::PortResult> items{
        make(22, portscan::PortState::Open, 3, "SSH-2.0-test"),
        make(23, portscan::PortState::Closed, 0, ""),
    };
    portscan::ScanReport report{"host", "127.0.0.1", items, 5};

    std::ostringstream out;
    portscan::writeTable(out, report);
    const auto text = out.str();

    CHECK(text.find("SSH-2.0-test") != std::string::npos);
    CHECK(text.find("scanned 2 ports on host (127.0.0.1) in 5 ms: 1 open, 1 closed, 0 filtered") != std::string::npos);
    CHECK(text.find("closed  ") == std::string::npos);
}

}

int main() {
    testCounts();
    testJsonLayout();
    testJsonEscapesBanner();
    testTableListsOnlyOpenPorts();

    if (g_failures == 0) {
        std::cout << "test_report: all tests passed\n";
        return 0;
    }
    std::cout << "test_report: " << g_failures << " checks failed\n";
    return 1;
}
