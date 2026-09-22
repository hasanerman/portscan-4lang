#include "report.h"

#include <string.h>

#define TABLE_WIDTH 56

void report_counts(const PortResult *results, size_t count, ScanCounts *out) {
    size_t i;

    memset(out, 0, sizeof(*out));
    for (i = 0; i < count; i++) {
        switch (results[i].state) {
        case PORT_OPEN:
            out->open++;
            break;
        case PORT_CLOSED:
            out->closed++;
            break;
        case PORT_FILTERED:
            out->filtered++;
            break;
        case PORT_ERROR:
            out->errors++;
            break;
        }
    }
}

void report_table(FILE *out, const ScanReport *report) {
    ScanCounts counts;
    size_t i;

    report_counts(report->results, report->count, &counts);
    fprintf(out, "%-7s %-9s %6s  %s\n", "PORT", "STATE", "MS", "BANNER");
    for (i = 0; i < TABLE_WIDTH; i++) {
        fputc('-', out);
    }
    fputc('\n', out);
    for (i = 0; i < report->count; i++) {
        const PortResult *item = &report->results[i];
        if (item->state == PORT_OPEN) {
            fprintf(out, "%-7u %-9s %6u  %s\n", (unsigned)item->port, port_state_name(item->state), item->ms,
                    item->banner);
        }
    }
    fprintf(out, "\nscanned %zu ports on %s (%s) in %llu ms: %zu open, %zu closed, %zu filtered", report->count,
            report->target, report->address, (unsigned long long)report->elapsed_ms, counts.open, counts.closed,
            counts.filtered);
    if (counts.errors > 0) {
        fprintf(out, ", %zu errors", counts.errors);
    }
    fputc('\n', out);
}

void report_json_string(FILE *out, const char *text) {
    const char *cursor;

    fputc('"', out);
    for (cursor = text; *cursor != '\0'; cursor++) {
        unsigned char value = (unsigned char)*cursor;
        if (value == '"' || value == '\\') {
            fputc('\\', out);
            fputc(value, out);
        } else if (value < 0x20) {
            fprintf(out, "\\u%04x", (unsigned)value);
        } else {
            fputc(value, out);
        }
    }
    fputc('"', out);
}

static void write_open_entry(FILE *out, const PortResult *item) {
    fprintf(out, "{\"port\":%u,\"state\":\"%s\",\"banner\":", (unsigned)item->port, port_state_name(item->state));
    report_json_string(out, item->banner);
    fprintf(out, ",\"ms\":%u}", item->ms);
}

void report_json(FILE *out, const ScanReport *report) {
    ScanCounts counts;
    size_t i;
    int first = 1;

    report_counts(report->results, report->count, &counts);
    fputs("{\"target\":", out);
    report_json_string(out, report->target);
    fputs(",\"address\":", out);
    report_json_string(out, report->address);
    fprintf(out, ",\"scanned\":%zu,\"open\":[", report->count);
    for (i = 0; i < report->count; i++) {
        if (report->results[i].state != PORT_OPEN) {
            continue;
        }
        if (!first) {
            fputc(',', out);
        }
        write_open_entry(out, &report->results[i]);
        first = 0;
    }
    fprintf(out, "],\"closed\":%zu,\"filtered\":%zu,\"errors\":%zu,\"elapsed_ms\":%llu}\n", counts.closed,
            counts.filtered, counts.errors, (unsigned long long)report->elapsed_ms);
}
