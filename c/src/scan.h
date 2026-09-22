#ifndef SCAN_H
#define SCAN_H

#include <stddef.h>
#include <stdint.h>

#include "net.h"

#define BANNER_MAX_CHARS 120
#define BANNER_READ_BYTES 1024
#define BANNER_WAIT_MS 500u

typedef enum { PORT_OPEN, PORT_CLOSED, PORT_FILTERED, PORT_ERROR } PortState;

typedef struct {
    uint16_t port;
    PortState state;
    unsigned ms;
    char banner[BANNER_MAX_CHARS + 1];
} PortResult;

typedef struct {
    NetAddress address;
    unsigned timeout_ms;
    int banner;
} ScanConfig;

const char *port_state_name(PortState state);
int scan_is_http_port(uint16_t port);
void scan_sanitize_banner(const unsigned char *data, size_t length, char *out, size_t out_len);
void scan_port(const ScanConfig *config, uint16_t port, PortResult *result);

#endif
