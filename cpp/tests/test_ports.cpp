#include "../src/Args.hpp"
#include "../src/Ports.hpp"

#include <array>
#include <iostream>
#include <span>
#include <string_view>
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

void testAcceptsValidSpecs() {
    auto single = portscan::parsePorts("22");
    CHECK(single.has_value() && single->size() == 1 && (*single)[0] == 22);

    auto range = portscan::parsePorts("1-10");
    CHECK(range.has_value() && range->size() == 10 && range->front() == 1 && range->back() == 10);

    auto list = portscan::parsePorts("22,80,443");
    CHECK(list.has_value() && list->size() == 3 && (*list)[2] == 443);

    auto deduped = portscan::parsePorts("80,22,80");
    CHECK(deduped.has_value() && deduped->size() == 2 && (*deduped)[0] == 22 && (*deduped)[1] == 80);

    auto overlap = portscan::parsePorts("1-3,2-5");
    CHECK(overlap.has_value() && overlap->size() == 5);

    auto boundary = portscan::parsePorts("65535");
    CHECK(boundary.has_value() && boundary->size() == 1 && (*boundary)[0] == 65535);

    auto full = portscan::parsePorts("1-65535");
    CHECK(full.has_value() && full->size() == 65535);
}

void testRejectsInvalidSpecs() {
    static constexpr std::array bad{"",   "0",     "65536",  "70000", "100-1",  "1-",   "-5",
                                    "a",  "22,,80", "22,",    ",22",   "1-2-3",  "-",    "12x",
                                    " 22", "99999999999999999999"};

    for (const auto* spec : bad) {
        auto result = portscan::parsePorts(spec);
        CHECK(!result.has_value());
    }
}

std::expected<portscan::Options, std::string> parse(std::vector<std::string_view> args) {
    return portscan::parseArgs(std::span<const std::string_view>{args});
}

void testArgsDefaultsAndFlags() {
    auto minimal = parse({"127.0.0.1"});
    CHECK(minimal.has_value());
    CHECK(minimal->target == "127.0.0.1");
    CHECK(minimal->portsSpec == "1-1024");
    CHECK(minimal->timeout == std::chrono::milliseconds{800});
    CHECK(minimal->concurrency == 500);
    CHECK(!minimal->banner && !minimal->confirmed && minimal->format == portscan::ReportFormat::Table);

    auto full = parse({"localhost", "--ports", "22,80", "--timeout", "250", "--concurrency", "64", "--banner",
                       "--format", "json", "--yes-i-own-this"});
    CHECK(full.has_value());
    CHECK(full->target == "localhost");
    CHECK(full->portsSpec == "22,80");
    CHECK(full->timeout == std::chrono::milliseconds{250});
    CHECK(full->concurrency == 64);
    CHECK(full->banner && full->confirmed && full->format == portscan::ReportFormat::Json);
}

void testArgsRejectsBadInput() {
    CHECK(!parse({}).has_value());
    CHECK(!parse({"a", "b"}).has_value());
    CHECK(!parse({"a", "--zoom"}).has_value());
    CHECK(!parse({"a", "--ports"}).has_value());
    CHECK(!parse({"a", "--timeout", "10"}).has_value());
    CHECK(!parse({"a", "--concurrency", "0"}).has_value());
    CHECK(!parse({"a", "--timeout", "abc"}).has_value());
    CHECK(!parse({"a", "--format", "xml"}).has_value());
    CHECK(parse({"--help"})->help);
}

}

int main() {
    testAcceptsValidSpecs();
    testRejectsInvalidSpecs();
    testArgsDefaultsAndFlags();
    testArgsRejectsBadInput();

    if (g_failures == 0) {
        std::cout << "test_ports: all tests passed\n";
        return 0;
    }
    std::cout << "test_ports: " << g_failures << " checks failed\n";
    return 1;
}
