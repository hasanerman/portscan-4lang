#ifndef ARGS_H
#define ARGS_H

#include <stddef.h>

#define TARGET_MAX 256
#define PORTS_SPEC_MAX 256

typedef enum { FORMAT_TABLE, FORMAT_JSON } ReportFormat;

typedef struct {
    char target[TARGET_MAX];
    char ports_spec[PORTS_SPEC_MAX];
    unsigned timeout_ms;
    unsigned concurrency;
    int banner;
    ReportFormat format;
    int confirmed;
} Options;

typedef enum { ARGS_OK = 0, ARGS_ERROR = 1, ARGS_HELP = 2 } ArgsStatus;

void args_defaults(Options *out);
ArgsStatus args_parse(int argc, char **argv, Options *out, char *err, size_t err_len);
const char *args_usage(void);

#endif
