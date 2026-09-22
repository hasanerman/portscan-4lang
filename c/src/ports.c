#include "ports.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NUMBER_TEXT_MAX 16

static void set_err(char *err, size_t err_len, const char *text) {
    if (err == NULL || err_len == 0) {
        return;
    }
    snprintf(err, err_len, "%s", text);
}

static int parse_port_number(const char *begin, size_t length, unsigned long *out) {
    char digits[NUMBER_TEXT_MAX];
    char *end = NULL;
    size_t i;

    if (length == 0 || length >= sizeof(digits)) {
        return 0;
    }
    for (i = 0; i < length; i++) {
        if (begin[i] < '0' || begin[i] > '9') {
            return 0;
        }
    }
    memcpy(digits, begin, length);
    digits[length] = '\0';
    errno = 0;
    *out = strtoul(digits, &end, 10);
    return errno == 0 && *end == '\0' && *out >= PORT_MIN && *out <= PORT_MAX;
}

static int mark_token(const char *begin, size_t length, unsigned char *flags, char *err, size_t err_len) {
    const char *dash = (const char *)memchr(begin, '-', length);
    unsigned long first = 0;
    unsigned long last = 0;
    unsigned long port;

    if (dash == NULL) {
        if (!parse_port_number(begin, length, &first)) {
            set_err(err, err_len, "port must be a number between 1 and 65535");
            return 0;
        }
        last = first;
    } else {
        size_t head = (size_t)(dash - begin);
        if (!parse_port_number(begin, head, &first) || !parse_port_number(dash + 1, length - head - 1, &last)) {
            set_err(err, err_len, "invalid port range");
            return 0;
        }
        if (first > last) {
            set_err(err, err_len, "port range start is greater than its end");
            return 0;
        }
    }
    for (port = first; port <= last; port++) {
        flags[port] = 1;
    }
    return 1;
}

static int mark_all_tokens(const char *spec, unsigned char *flags, char *err, size_t err_len) {
    const char *cursor = spec;

    for (;;) {
        const char *comma = strchr(cursor, ',');
        size_t length = comma == NULL ? strlen(cursor) : (size_t)(comma - cursor);

        if (!mark_token(cursor, length, flags, err, err_len)) {
            return 0;
        }
        if (comma == NULL) {
            return 1;
        }
        cursor = comma + 1;
    }
}

int ports_parse(const char *spec, PortList *out, char *err, size_t err_len) {
    unsigned char *flags;
    size_t count = 0;
    size_t index = 0;
    size_t port;

    out->items = NULL;
    out->count = 0;

    if (spec == NULL || spec[0] == '\0') {
        set_err(err, err_len, "port list is empty");
        return 0;
    }
    flags = (unsigned char *)calloc((size_t)PORT_MAX + 1u, 1);
    if (flags == NULL) {
        set_err(err, err_len, "out of memory");
        return 0;
    }
    if (!mark_all_tokens(spec, flags, err, err_len)) {
        free(flags);
        return 0;
    }
    for (port = PORT_MIN; port <= PORT_MAX; port++) {
        count += flags[port] ? 1u : 0u;
    }
    out->items = (uint16_t *)malloc(count * sizeof(uint16_t));
    if (out->items == NULL) {
        free(flags);
        set_err(err, err_len, "out of memory");
        return 0;
    }
    for (port = PORT_MIN; port <= PORT_MAX; port++) {
        if (flags[port]) {
            out->items[index++] = (uint16_t)port;
        }
    }
    out->count = count;
    free(flags);
    return 1;
}

void ports_free(PortList *list) {
    free(list->items);
    list->items = NULL;
    list->count = 0;
}
