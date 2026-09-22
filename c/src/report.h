#ifndef REPORT_H
#define REPORT_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "scan.h"

typedef struct {
    size_t open;
    size_t closed;
    size_t filtered;
    size_t errors;
} ScanCounts;

typedef struct {
    const char *target;
    const char *address;
    const PortResult *results;
    size_t count;
    uint64_t elapsed_ms;
} ScanReport;

void report_counts(const PortResult *results, size_t count, ScanCounts *out);
void report_table(FILE *out, const ScanReport *report);
void report_json(FILE *out, const ScanReport *report);
void report_json_string(FILE *out, const char *text);

#endif
