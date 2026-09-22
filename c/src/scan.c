#include "scan.h"

#include <string.h>

#define HTTP_PROBE "HEAD / HTTP/1.0\r\n\r\n"
#define MICROS_PER_MILLI 1000u
#define PRINTABLE_FIRST 0x20
#define PRINTABLE_LAST 0x7e

const char *port_state_name(PortState state) {
    switch (state) {
    case PORT_OPEN:
        return "open";
    case PORT_CLOSED:
        return "closed";
    case PORT_FILTERED:
        return "filtered";
    case PORT_ERROR:
        return "error";
    }
    return "error";
}

int scan_is_http_port(uint16_t port) {
    return port == 80 || port == 8000 || port == 8080 || port == 8888;
}

void scan_sanitize_banner(const unsigned char *data, size_t length, char *out, size_t out_len) {
    size_t written = 0;
    size_t i = 0;

    if (out_len == 0) {
        return;
    }
    while (i < length && (data[i] == '\r' || data[i] == '\n' || data[i] == ' ')) {
        i++;
    }
    while (i < length && data[i] != '\r' && data[i] != '\n' && written + 1 < out_len) {
        unsigned char value = data[i];
        out[written++] = (value >= PRINTABLE_FIRST && value <= PRINTABLE_LAST) ? (char)value : '.';
        i++;
    }
    while (written > 0 && out[written - 1] == ' ') {
        written--;
    }
    out[written] = '\0';
}

static unsigned elapsed_ms(uint64_t start_us) {
    uint64_t elapsed = net_now_us() - start_us;

    return (unsigned)((elapsed + MICROS_PER_MILLI / 2) / MICROS_PER_MILLI);
}

static PortState state_for(ConnectOutcome outcome) {
    if (outcome == OUTCOME_CLOSED) {
        return PORT_CLOSED;
    }
    return outcome == OUTCOME_FILTERED ? PORT_FILTERED : PORT_ERROR;
}

static PortState connect_port(const NetAddress *address, unsigned timeout_ms, sock_t *out) {
    sock_t handle = net_open(address);
    WaitResult waited;
    int error = 0;

    *out = SOCK_INVALID;
    if (handle == SOCK_INVALID) {
        return PORT_ERROR;
    }
    switch (net_connect(handle, address, &error)) {
    case CONNECT_DONE:
        *out = handle;
        return PORT_OPEN;
    case CONNECT_PENDING:
        waited = net_wait(handle, 1, timeout_ms);
        if (waited == WAIT_RES_TIMEOUT) {
            net_close(handle);
            return PORT_FILTERED;
        }
        error = waited == WAIT_RES_READY ? net_socket_error(handle) : -1;
        if (error == 0) {
            *out = handle;
            return PORT_OPEN;
        }
        break;
    case CONNECT_FAILED:
        break;
    }
    net_close(handle);
    return state_for(net_classify(error));
}

static void read_banner(sock_t handle, uint16_t port, unsigned timeout_ms, char *out, size_t out_len) {
    unsigned char buffer[BANNER_READ_BYTES];
    unsigned wait_ms = timeout_ms < BANNER_WAIT_MS ? timeout_ms : BANNER_WAIT_MS;
    long received;

    out[0] = '\0';
    if (scan_is_http_port(port) && net_send(handle, HTTP_PROBE, strlen(HTTP_PROBE)) < 0) {
        return;
    }
    if (net_wait(handle, 0, wait_ms) != WAIT_RES_READY) {
        return;
    }
    received = net_recv(handle, buffer, sizeof(buffer));
    if (received > 0) {
        scan_sanitize_banner(buffer, (size_t)received, out, out_len);
    }
}

void scan_port(const ScanConfig *config, uint16_t port, PortResult *result) {
    NetAddress target = config->address;
    sock_t handle = SOCK_INVALID;
    uint64_t start = net_now_us();

    memset(result, 0, sizeof(*result));
    result->port = port;
    net_set_port(&target, port);
    result->state = connect_port(&target, config->timeout_ms, &handle);
    result->ms = elapsed_ms(start);
    if (handle == SOCK_INVALID) {
        return;
    }
    if (config->banner) {
        read_banner(handle, port, config->timeout_ms, result->banner, sizeof(result->banner));
    }
    net_close(handle);
}
