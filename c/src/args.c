#include "args.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DEFAULT_PORTS "1-1024"
#define DEFAULT_TIMEOUT_MS 800u
#define DEFAULT_CONCURRENCY 500u
#define MIN_TIMEOUT_MS 50u
#define MAX_TIMEOUT_MS 60000u
#define MIN_CONCURRENCY 1u
#define MAX_CONCURRENCY 10000u

static void set_err(char *err, size_t err_len, const char *text) {
    if (err == NULL || err_len == 0) {
        return;
    }
    snprintf(err, err_len, "%s", text);
}

static int parse_ulong(const char *text, unsigned long *out) {
    char *end = NULL;

    if (text == NULL || *text < '0' || *text > '9') {
        return 0;
    }
    errno = 0;
    *out = strtoul(text, &end, 10);
    return errno == 0 && *end == '\0';
}

static int is_value_flag(const char *arg) {
    return strcmp(arg, "--ports") == 0 || strcmp(arg, "--timeout") == 0 ||
           strcmp(arg, "--concurrency") == 0 || strcmp(arg, "--format") == 0;
}

static ArgsStatus apply_number(const char *flag, const char *value, Options *out, char *err, size_t err_len) {
    unsigned long number = 0;

    if (!parse_ulong(value, &number)) {
        set_err(err, err_len, "a number was expected");
        return ARGS_ERROR;
    }
    if (strcmp(flag, "--timeout") == 0) {
        if (number < MIN_TIMEOUT_MS || number > MAX_TIMEOUT_MS) {
            set_err(err, err_len, "timeout must be between 50 and 60000 ms");
            return ARGS_ERROR;
        }
        out->timeout_ms = (unsigned)number;
    } else {
        if (number < MIN_CONCURRENCY || number > MAX_CONCURRENCY) {
            set_err(err, err_len, "concurrency must be between 1 and 10000");
            return ARGS_ERROR;
        }
        out->concurrency = (unsigned)number;
    }
    return ARGS_OK;
}

static ArgsStatus apply_value(const char *flag, const char *value, Options *out, char *err, size_t err_len) {
    if (strcmp(flag, "--ports") == 0) {
        if (strlen(value) >= sizeof(out->ports_spec)) {
            set_err(err, err_len, "port list is too long");
            return ARGS_ERROR;
        }
        snprintf(out->ports_spec, sizeof(out->ports_spec), "%s", value);
        return ARGS_OK;
    }
    if (strcmp(flag, "--format") == 0) {
        if (strcmp(value, "table") == 0) {
            out->format = FORMAT_TABLE;
        } else if (strcmp(value, "json") == 0) {
            out->format = FORMAT_JSON;
        } else {
            set_err(err, err_len, "format must be table or json");
            return ARGS_ERROR;
        }
        return ARGS_OK;
    }
    return apply_number(flag, value, out, err, err_len);
}

void args_defaults(Options *out) {
    memset(out, 0, sizeof(*out));
    snprintf(out->ports_spec, sizeof(out->ports_spec), "%s", DEFAULT_PORTS);
    out->timeout_ms = DEFAULT_TIMEOUT_MS;
    out->concurrency = DEFAULT_CONCURRENCY;
    out->format = FORMAT_TABLE;
}

const char *args_usage(void) {
    return "portscan <target> [--ports 1-1024|22,80,443] [--timeout <ms>] [--concurrency <n>]\n"
           "                 [--banner] [--format table|json] [--yes-i-own-this] [--help]\n";
}

static ArgsStatus take_positional(const char *arg, Options *out, char *err, size_t err_len) {
    if (out->target[0] != '\0') {
        set_err(err, err_len, "only one target is allowed");
        return ARGS_ERROR;
    }
    if (strlen(arg) >= sizeof(out->target)) {
        set_err(err, err_len, "target is too long");
        return ARGS_ERROR;
    }
    snprintf(out->target, sizeof(out->target), "%s", arg);
    return ARGS_OK;
}

ArgsStatus args_parse(int argc, char **argv, Options *out, char *err, size_t err_len) {
    int i;

    args_defaults(out);

    for (i = 1; i < argc; i++) {
        const char *arg = argv[i];
        ArgsStatus status = ARGS_OK;

        if (strcmp(arg, "--help") == 0 || strcmp(arg, "-h") == 0) {
            return ARGS_HELP;
        }
        if (strcmp(arg, "--banner") == 0) {
            out->banner = 1;
        } else if (strcmp(arg, "--yes-i-own-this") == 0) {
            out->confirmed = 1;
        } else if (is_value_flag(arg)) {
            if (i + 1 >= argc) {
                set_err(err, err_len, "a value is missing");
                return ARGS_ERROR;
            }
            status = apply_value(arg, argv[++i], out, err, err_len);
        } else if (strncmp(arg, "--", 2) == 0) {
            set_err(err, err_len, "unknown argument");
            return ARGS_ERROR;
        } else {
            status = take_positional(arg, out, err, err_len);
        }
        if (status != ARGS_OK) {
            return status;
        }
    }

    if (out->target[0] == '\0') {
        set_err(err, err_len, "a target is required");
        return ARGS_ERROR;
    }
    return ARGS_OK;
}
