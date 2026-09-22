#include <stdio.h>
#include <string.h>

#include "../src/report.h"

#define SCRATCH_FILE "report_test.tmp"
#define OUTPUT_MAX 2048

static int g_failures;

#define CHECK(condition)                                               \
    do {                                                               \
        if (!(condition)) {                                            \
            printf("FAIL %s:%d %s\n", __FILE__, __LINE__, #condition); \
            g_failures++;                                              \
        }                                                              \
    } while (0)

static void fill(PortResult *item, uint16_t port, PortState state, unsigned ms, const char *banner) {
    memset(item, 0, sizeof(*item));
    item->port = port;
    item->state = state;
    item->ms = ms;
    snprintf(item->banner, sizeof(item->banner), "%s", banner);
}

static int capture(void (*writer)(FILE *, const ScanReport *), const ScanReport *report, char *out, size_t out_len) {
    FILE *file = fopen(SCRATCH_FILE, "w+");
    size_t read_bytes;

    if (file == NULL) {
        return 0;
    }
    writer(file, report);
    rewind(file);
    read_bytes = fread(out, 1, out_len - 1, file);
    out[read_bytes] = '\0';
    fclose(file);
    remove(SCRATCH_FILE);
    return 1;
}

static void test_counts(void) {
    PortResult items[5];
    ScanCounts counts;

    fill(&items[0], 22, PORT_OPEN, 1, "");
    fill(&items[1], 23, PORT_CLOSED, 0, "");
    fill(&items[2], 24, PORT_CLOSED, 0, "");
    fill(&items[3], 25, PORT_FILTERED, 800, "");
    fill(&items[4], 26, PORT_ERROR, 0, "");
    report_counts(items, 5, &counts);
    CHECK(counts.open == 1 && counts.closed == 2 && counts.filtered == 1 && counts.errors == 1);
}

static void test_json_layout(void) {
    PortResult items[3];
    ScanReport report;
    char output[OUTPUT_MAX];

    fill(&items[0], 22, PORT_OPEN, 2, "SSH-2.0-test");
    fill(&items[1], 23, PORT_CLOSED, 0, "");
    fill(&items[2], 24, PORT_FILTERED, 800, "");
    report.target = "host";
    report.address = "127.0.0.1";
    report.results = items;
    report.count = 3;
    report.elapsed_ms = 9;

    CHECK(capture(report_json, &report, output, sizeof(output)));
    CHECK(strcmp(output,
                 "{\"target\":\"host\",\"address\":\"127.0.0.1\",\"scanned\":3,\"open\":[{\"port\":22,\"state\":"
                 "\"open\",\"banner\":\"SSH-2.0-test\",\"ms\":2}],\"closed\":1,\"filtered\":1,\"errors\":0,"
                 "\"elapsed_ms\":9}\n") == 0);
}

static void test_json_escapes_banner(void) {
    PortResult items[1];
    ScanReport report;
    char output[OUTPUT_MAX];

    fill(&items[0], 80, PORT_OPEN, 1, "say \"hi\" \\ done");
    report.target = "t";
    report.address = "127.0.0.1";
    report.results = items;
    report.count = 1;
    report.elapsed_ms = 1;

    CHECK(capture(report_json, &report, output, sizeof(output)));
    CHECK(strstr(output, "\"banner\":\"say \\\"hi\\\" \\\\ done\"") != NULL);
}

static void test_table_lists_only_open_ports(void) {
    PortResult items[2];
    ScanReport report;
    char output[OUTPUT_MAX];

    fill(&items[0], 22, PORT_OPEN, 3, "SSH-2.0-test");
    fill(&items[1], 23, PORT_CLOSED, 0, "");
    report.target = "host";
    report.address = "127.0.0.1";
    report.results = items;
    report.count = 2;
    report.elapsed_ms = 5;

    CHECK(capture(report_table, &report, output, sizeof(output)));
    CHECK(strstr(output, "SSH-2.0-test") != NULL);
    CHECK(strstr(output, "scanned 2 ports on host (127.0.0.1) in 5 ms: 1 open, 1 closed, 0 filtered") != NULL);
    CHECK(strstr(output, "closed  ") == NULL);
}

int main(void) {
    test_counts();
    test_json_layout();
    test_json_escapes_banner();
    test_table_lists_only_open_ports();

    if (g_failures == 0) {
        printf("test_report: all tests passed\n");
        return 0;
    }
    printf("test_report: %d checks failed\n", g_failures);
    return 1;
}
