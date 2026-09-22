#include <stdio.h>
#include <stdlib.h>

#include "args.h"
#include "net.h"
#include "pool.h"
#include "ports.h"
#include "report.h"
#include "scan.h"

#define EXIT_OK 0
#define EXIT_USAGE 1
#define EXIT_UNRESOLVED 2
#define THREAD_LIMIT 512u
#define MICROS_PER_MILLI 1000u

typedef struct {
    const ScanConfig *config;
    const PortList *ports;
    PortResult *results;
} ScanJob;

static void scan_task(size_t index, void *context) {
    ScanJob *job = (ScanJob *)context;

    scan_port(job->config, job->ports->items[index], &job->results[index]);
}

static unsigned worker_count(unsigned requested, size_t port_count) {
    unsigned workers = requested;

    if (workers > THREAD_LIMIT) {
        fprintf(stderr, "note: the thread-based scanner limits concurrency to %u\n", THREAD_LIMIT);
        workers = THREAD_LIMIT;
    }
    return port_count < workers ? (unsigned)port_count : workers;
}

static int is_scan_allowed(const Options *options, const NetAddress *address) {
    if (net_is_local(address)) {
        return 1;
    }
    if (options->confirmed) {
        fputs("note: scanning a non-local target\n", stderr);
        return 1;
    }
    fprintf(stderr,
            "error: %s is not a local or private address; pass --yes-i-own-this only if you own it or have "
            "permission to scan it\n",
            options->target);
    return 0;
}

static int run_scan(const Options *options, const PortList *ports, const NetAddress *address, const char *text) {
    ScanConfig config;
    ScanJob job;
    ScanReport report;
    unsigned workers = worker_count(options->concurrency, ports->count);
    size_t started;
    uint64_t begin;
    PortResult *results = (PortResult *)calloc(ports->count, sizeof(PortResult));

    if (results == NULL) {
        fputs("error: out of memory\n", stderr);
        return EXIT_USAGE;
    }
    config.address = *address;
    config.timeout_ms = options->timeout_ms;
    config.banner = options->banner;
    job.config = &config;
    job.ports = ports;
    job.results = results;

    begin = net_now_us();
    started = pool_run(ports->count, workers, scan_task, &job);
    if (started < workers) {
        fprintf(stderr, "note: only %zu of %u worker threads could be started\n", started, workers);
    }

    report.target = options->target;
    report.address = text;
    report.results = results;
    report.count = ports->count;
    report.elapsed_ms = (net_now_us() - begin) / MICROS_PER_MILLI;
    if (options->format == FORMAT_JSON) {
        report_json(stdout, &report);
    } else {
        report_table(stdout, &report);
    }
    free(results);
    return EXIT_OK;
}

static int prepare_and_scan(const Options *options) {
    PortList ports;
    NetAddress address;
    char text[ADDRESS_TEXT_MAX];
    char error[128];
    int code;

    if (!ports_parse(options->ports_spec, &ports, error, sizeof(error))) {
        fprintf(stderr, "error: %s\n", error);
        return EXIT_USAGE;
    }
    if (!net_resolve(options->target, &address) || !net_format(&address, text, sizeof(text))) {
        fprintf(stderr, "error: cannot resolve %s\n", options->target);
        ports_free(&ports);
        return EXIT_UNRESOLVED;
    }
    code = is_scan_allowed(options, &address) ? run_scan(options, &ports, &address, text) : EXIT_USAGE;
    ports_free(&ports);
    return code;
}

int main(int argc, char **argv) {
    Options options;
    char error[128];
    ArgsStatus status = args_parse(argc, argv, &options, error, sizeof(error));
    int code;

    if (status == ARGS_HELP) {
        fputs(args_usage(), stdout);
        return EXIT_OK;
    }
    if (status == ARGS_ERROR) {
        fprintf(stderr, "error: %s\n%s", error, args_usage());
        return EXIT_USAGE;
    }
    if (!net_init()) {
        fputs("error: network initialisation failed\n", stderr);
        return EXIT_UNRESOLVED;
    }
    code = prepare_and_scan(&options);
    net_cleanup();
    return code;
}
