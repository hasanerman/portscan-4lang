#include <stdio.h>
#include <string.h>

#include "../src/args.h"
#include "../src/ports.h"

static int g_failures;

#define CHECK(condition)                                               \
    do {                                                               \
        if (!(condition)) {                                            \
            printf("FAIL %s:%d %s\n", __FILE__, __LINE__, #condition); \
            g_failures++;                                              \
        }                                                              \
    } while (0)

static int parse(const char *spec, PortList *list) {
    char err[128];

    return ports_parse(spec, list, err, sizeof(err));
}

static void test_accepts_valid_specs(void) {
    PortList list;

    CHECK(parse("22", &list) && list.count == 1 && list.items[0] == 22);
    ports_free(&list);
    CHECK(parse("1-10", &list) && list.count == 10 && list.items[0] == 1 && list.items[9] == 10);
    ports_free(&list);
    CHECK(parse("22,80,443", &list) && list.count == 3 && list.items[2] == 443);
    ports_free(&list);
    CHECK(parse("80,22,80", &list) && list.count == 2 && list.items[0] == 22 && list.items[1] == 80);
    ports_free(&list);
    CHECK(parse("1-3,2-5", &list) && list.count == 5);
    ports_free(&list);
    CHECK(parse("65535", &list) && list.count == 1 && list.items[0] == 65535);
    ports_free(&list);
    CHECK(parse("1-65535", &list) && list.count == 65535);
    ports_free(&list);
}

static void test_rejects_invalid_specs(void) {
    const char *bad[] = {"",     "0",   "65536", "70000", "100-1", "1-",  "-5",  "a",
                         "22,,80", "22,", ",22",  "1-2-3", "-",     "12x", " 22", "99999999999999999999"};
    size_t i;

    for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        PortList list;
        int accepted = parse(bad[i], &list);

        CHECK(!accepted);
        CHECK(list.items == NULL && list.count == 0);
    }
}

static ArgsStatus parse_args(char **argv, int argc, Options *options) {
    char err[128];

    return args_parse(argc, argv, options, err, sizeof(err));
}

static void test_args_defaults_and_flags(void) {
    Options options;
    char *minimal[] = {"portscan", "127.0.0.1"};
    char *full[] = {"portscan", "localhost", "--ports", "22,80", "--timeout", "250", "--concurrency", "64",
                    "--banner", "--format", "json", "--yes-i-own-this"};

    CHECK(parse_args(minimal, 2, &options) == ARGS_OK);
    CHECK(strcmp(options.target, "127.0.0.1") == 0);
    CHECK(strcmp(options.ports_spec, "1-1024") == 0);
    CHECK(options.timeout_ms == 800 && options.concurrency == 500);
    CHECK(!options.banner && !options.confirmed && options.format == FORMAT_TABLE);

    CHECK(parse_args(full, 12, &options) == ARGS_OK);
    CHECK(strcmp(options.target, "localhost") == 0);
    CHECK(strcmp(options.ports_spec, "22,80") == 0);
    CHECK(options.timeout_ms == 250 && options.concurrency == 64);
    CHECK(options.banner && options.confirmed && options.format == FORMAT_JSON);
}

static void test_args_rejects_bad_input(void) {
    Options options;
    char *no_target[] = {"portscan"};
    char *two_targets[] = {"portscan", "a", "b"};
    char *unknown[] = {"portscan", "a", "--zoom"};
    char *missing[] = {"portscan", "a", "--ports"};
    char *low_timeout[] = {"portscan", "a", "--timeout", "10"};
    char *zero_concurrency[] = {"portscan", "a", "--concurrency", "0"};
    char *text_timeout[] = {"portscan", "a", "--timeout", "abc"};
    char *bad_format[] = {"portscan", "a", "--format", "xml"};
    char *help[] = {"portscan", "--help"};

    CHECK(parse_args(no_target, 1, &options) == ARGS_ERROR);
    CHECK(parse_args(two_targets, 3, &options) == ARGS_ERROR);
    CHECK(parse_args(unknown, 3, &options) == ARGS_ERROR);
    CHECK(parse_args(missing, 3, &options) == ARGS_ERROR);
    CHECK(parse_args(low_timeout, 4, &options) == ARGS_ERROR);
    CHECK(parse_args(zero_concurrency, 4, &options) == ARGS_ERROR);
    CHECK(parse_args(text_timeout, 4, &options) == ARGS_ERROR);
    CHECK(parse_args(bad_format, 4, &options) == ARGS_ERROR);
    CHECK(parse_args(help, 2, &options) == ARGS_HELP);
}

int main(void) {
    test_accepts_valid_specs();
    test_rejects_invalid_specs();
    test_args_defaults_and_flags();
    test_args_rejects_bad_input();

    if (g_failures == 0) {
        printf("test_ports: all tests passed\n");
        return 0;
    }
    printf("test_ports: %d checks failed\n", g_failures);
    return 1;
}
