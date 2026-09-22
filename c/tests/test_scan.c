#include <stdio.h>
#include <string.h>

#include "../src/net.h"
#include "../src/pool.h"
#include "../src/scan.h"

#ifdef _WIN32
typedef int addr_len_t;
#else
#include <errno.h>
typedef socklen_t addr_len_t;
#endif

#define RANGE_SIZE 200
#define ROUNDS 20
#define CONNECT_TIMEOUT_MS 2000u

static int g_failures;

#define CHECK(condition)                                               \
    do {                                                               \
        if (!(condition)) {                                            \
            printf("FAIL %s:%d %s\n", __FILE__, __LINE__, #condition); \
            g_failures++;                                              \
        }                                                              \
    } while (0)

static int is_local_text(const char *text) {
    NetAddress address;

    return net_parse_literal(text, &address) && net_is_local(&address);
}

static void test_local_address_detection(void) {
    NetAddress address;

    CHECK(is_local_text("127.0.0.1"));
    CHECK(is_local_text("10.1.2.3"));
    CHECK(is_local_text("172.16.0.1"));
    CHECK(is_local_text("172.31.255.255"));
    CHECK(is_local_text("192.168.1.1"));
    CHECK(is_local_text("169.254.1.1"));
    CHECK(is_local_text("0.0.0.0"));
    CHECK(is_local_text("::1"));
    CHECK(is_local_text("fe80::1"));
    CHECK(is_local_text("fd00::1"));
    CHECK(is_local_text("::ffff:10.0.0.1"));
    CHECK(!is_local_text("8.8.8.8"));
    CHECK(!is_local_text("1.1.1.1"));
    CHECK(!is_local_text("172.32.0.1"));
    CHECK(!is_local_text("172.15.0.1"));
    CHECK(!is_local_text("192.169.0.1"));
    CHECK(!is_local_text("2001:4860:4860::8888"));
    CHECK(!is_local_text("::ffff:8.8.8.8"));
    CHECK(!net_parse_literal("not-an-ip", &address));
    CHECK(!net_parse_literal("999.1.1.1", &address));
}

static void test_classify(void) {
#ifdef _WIN32
    CHECK(net_classify(WSAECONNREFUSED) == OUTCOME_CLOSED);
    CHECK(net_classify(WSAETIMEDOUT) == OUTCOME_FILTERED);
    CHECK(net_classify(WSAEHOSTUNREACH) == OUTCOME_FILTERED);
    CHECK(net_classify(WSAEMFILE) == OUTCOME_ERROR);
#else
    CHECK(net_classify(ECONNREFUSED) == OUTCOME_CLOSED);
    CHECK(net_classify(ETIMEDOUT) == OUTCOME_FILTERED);
    CHECK(net_classify(EHOSTUNREACH) == OUTCOME_FILTERED);
    CHECK(net_classify(EMFILE) == OUTCOME_ERROR);
#endif
}

static void test_sanitize_banner(void) {
    char out[BANNER_MAX_CHARS + 1];
    const unsigned char ssh[] = "SSH-2.0-OpenSSH_9.6\r\nextra";
    const unsigned char binary[] = {'A', 0x01, 'B', 0xff, 'C'};
    const unsigned char padded[] = "\r\n  220 hello  \r\n";
    unsigned char longer[300];

    scan_sanitize_banner(ssh, sizeof(ssh) - 1, out, sizeof(out));
    CHECK(strcmp(out, "SSH-2.0-OpenSSH_9.6") == 0);
    scan_sanitize_banner(binary, sizeof(binary), out, sizeof(out));
    CHECK(strcmp(out, "A.B.C") == 0);
    scan_sanitize_banner(padded, sizeof(padded) - 1, out, sizeof(out));
    CHECK(strcmp(out, "220 hello") == 0);
    memset(longer, 'x', sizeof(longer));
    scan_sanitize_banner(longer, sizeof(longer), out, sizeof(out));
    CHECK(strlen(out) == BANNER_MAX_CHARS);
    scan_sanitize_banner(ssh, 0, out, sizeof(out));
    CHECK(out[0] == '\0');
}

static void test_http_ports(void) {
    CHECK(scan_is_http_port(80) && scan_is_http_port(8080) && scan_is_http_port(8000) && scan_is_http_port(8888));
    CHECK(!scan_is_http_port(22) && !scan_is_http_port(443));
}

static sock_t open_listener(uint16_t *port) {
    NetAddress address;
    struct sockaddr_in bound;
    addr_len_t length = (addr_len_t)sizeof(bound);
    sock_t handle;

    net_parse_literal("127.0.0.1", &address);
    net_set_port(&address, 0);
    handle = socket(AF_INET, SOCK_STREAM, 0);
    if (handle == SOCK_INVALID) {
        return SOCK_INVALID;
    }
    if (bind(handle, (const struct sockaddr *)&address.storage, (addr_len_t)address.length) != 0 ||
        listen(handle, 512) != 0 || getsockname(handle, (struct sockaddr *)&bound, &length) != 0) {
        net_close(handle);
        return SOCK_INVALID;
    }
    *port = ntohs(bound.sin_port);
    return handle;
}

static void make_config(ScanConfig *config, int banner) {
    net_parse_literal("127.0.0.1", &config->address);
    config->timeout_ms = CONNECT_TIMEOUT_MS;
    config->banner = banner;
}

static void test_open_and_closed_ports(void) {
    ScanConfig config;
    PortResult result;
    uint16_t port = 0;
    sock_t listener = open_listener(&port);

    CHECK(listener != SOCK_INVALID);
    make_config(&config, 0);
    scan_port(&config, port, &result);
    CHECK(result.state == PORT_OPEN);
    net_close(listener);
    scan_port(&config, port, &result);
    CHECK(result.state == PORT_CLOSED);
}

typedef struct {
    sock_t listener;
    ScanConfig config;
    uint16_t port;
    PortResult result;
} BannerJob;

static void serve_banner(sock_t listener) {
    static const char text[] = "220 izci test ready\r\n";
    sock_t client;

    if (net_wait(listener, 0, 3000) != WAIT_RES_READY) {
        return;
    }
    client = accept(listener, NULL, NULL);
    if (client == SOCK_INVALID) {
        return;
    }
    net_send(client, text, sizeof(text) - 1);
    net_wait(client, 0, 1000);
    net_close(client);
}

static void banner_task(size_t index, void *context) {
    BannerJob *job = (BannerJob *)context;

    if (index == 0) {
        serve_banner(job->listener);
    } else {
        scan_port(&job->config, job->port, &job->result);
    }
}

static void test_banner_grab(void) {
    BannerJob job;

    memset(&job, 0, sizeof(job));
    job.listener = open_listener(&job.port);
    CHECK(job.listener != SOCK_INVALID);
    make_config(&job.config, 1);
    pool_run(2, 2, banner_task, &job);
    CHECK(job.result.state == PORT_OPEN);
    CHECK(strcmp(job.result.banner, "220 izci test ready") == 0);
    net_close(job.listener);
}

typedef struct {
    const ScanConfig *config;
    uint16_t first;
    PortResult *results;
} RangeJob;

static void range_task(size_t index, void *context) {
    RangeJob *job = (RangeJob *)context;

    scan_port(job->config, (uint16_t)(job->first + index), &job->results[index]);
}

static int results_are_ordered(const PortResult *results, uint16_t first) {
    size_t i;

    for (i = 0; i < RANGE_SIZE; i++) {
        if (results[i].port != (uint16_t)(first + i)) {
            return 0;
        }
    }
    return 1;
}

/*
 * Only the port this test owns is asserted on. The rest of the window sits in
 * the OS ephemeral range, where unrelated processes claim and release ports
 * while the scan runs. Repetition proves that our scanner keeps returning a
 * complete, correctly ordered result set and never loses the one port we
 * control, which is what a socket leak would break.
 */
static void test_repeated_scans_are_stable(void) {
    static PortResult results[RANGE_SIZE];
    ScanConfig config;
    RangeJob job;
    uint16_t port = 0;
    sock_t listener = open_listener(&port);
    uint16_t first = (uint16_t)(port - RANGE_SIZE / 2);
    int round;

    CHECK(listener != SOCK_INVALID);
    make_config(&config, 0);
    job.config = &config;
    job.first = first;
    job.results = results;

    for (round = 0; round <= ROUNDS; round++) {
        pool_run(RANGE_SIZE, 64, range_task, &job);
        CHECK(results_are_ordered(results, first));
        CHECK(results[port - first].state == PORT_OPEN);
    }
    net_close(listener);
}

int main(void) {
    if (!net_init()) {
        printf("test_scan: network initialisation failed\n");
        return 1;
    }
    test_local_address_detection();
    test_classify();
    test_sanitize_banner();
    test_http_ports();
    test_open_and_closed_ports();
    test_banner_grab();
    test_repeated_scans_are_stable();
    net_cleanup();

    if (g_failures == 0) {
        printf("test_scan: all tests passed\n");
        return 0;
    }
    printf("test_scan: %d checks failed\n", g_failures);
    return 1;
}
