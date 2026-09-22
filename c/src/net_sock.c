#include "net.h"

#ifdef _WIN32
#include <mstcpip.h>
#else
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <time.h>
#include <unistd.h>
#endif

#define MICROS_PER_SECOND 1000000u
#define NANOS_PER_MICRO 1000u
#define MILLIS_PER_SECOND 1000u
#define MICROS_PER_MILLI 1000u

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

static int make_nonblocking(sock_t handle) {
#ifdef _WIN32
    u_long enabled = 1;
    return ioctlsocket(handle, FIONBIO, &enabled) == 0;
#else
    int flags = fcntl(handle, F_GETFL, 0);
    return flags >= 0 && fcntl(handle, F_SETFL, flags | O_NONBLOCK) == 0;
#endif
}

static void disable_syn_retransmission(sock_t handle) {
#ifdef _WIN32
    TCP_INITIAL_RTO_PARAMETERS parameters;
    DWORD returned = 0;

    parameters.Rtt = TCP_INITIAL_RTO_UNSPECIFIED_RTT;
    parameters.MaxSynRetransmissions = TCP_INITIAL_RTO_NO_SYN_RETRANSMISSIONS;
    WSAIoctl(handle, SIO_TCP_INITIAL_RTO, &parameters, sizeof(parameters), NULL, 0, &returned, NULL, NULL);
#else
    (void)handle;
#endif
}

sock_t net_open(const NetAddress *address) {
    sock_t handle = socket(address->family, SOCK_STREAM, 0);

    if (handle == SOCK_INVALID) {
        return SOCK_INVALID;
    }
    if (!make_nonblocking(handle)) {
        net_close(handle);
        return SOCK_INVALID;
    }
    disable_syn_retransmission(handle);
    return handle;
}

void net_close(sock_t handle) {
#ifdef _WIN32
    closesocket(handle);
#else
    close(handle);
#endif
}

static int last_socket_error(void) {
#ifdef _WIN32
    return WSAGetLastError();
#else
    return errno;
#endif
}

static int is_in_progress(int error) {
#ifdef _WIN32
    return error == WSAEWOULDBLOCK || error == WSAEINPROGRESS;
#else
    return error == EINPROGRESS || error == EINTR;
#endif
}

ConnectResult net_connect(sock_t handle, const NetAddress *address, int *error) {
    int status = connect(handle, (const struct sockaddr *)&address->storage, (int)address->length);

    *error = 0;
    if (status == 0) {
        return CONNECT_DONE;
    }
    *error = last_socket_error();
    return is_in_progress(*error) ? CONNECT_PENDING : CONNECT_FAILED;
}

WaitResult net_wait(sock_t handle, int for_write, unsigned timeout_ms) {
#ifdef _WIN32
    fd_set primary;
    fd_set failed;
    struct timeval limit;
    int status;

    FD_ZERO(&primary);
    FD_ZERO(&failed);
    FD_SET(handle, &primary);
    FD_SET(handle, &failed);
    limit.tv_sec = (long)(timeout_ms / MILLIS_PER_SECOND);
    limit.tv_usec = (long)((timeout_ms % MILLIS_PER_SECOND) * MICROS_PER_MILLI);
    status = select(0, for_write ? NULL : &primary, for_write ? &primary : NULL, &failed, &limit);
    if (status == 0) {
        return WAIT_RES_TIMEOUT;
    }
    return status < 0 ? WAIT_RES_FAILED : WAIT_RES_READY;
#else
    struct pollfd item;
    int status;

    item.fd = handle;
    item.events = for_write ? POLLOUT : POLLIN;
    item.revents = 0;
    do {
        status = poll(&item, 1, (int)timeout_ms);
    } while (status < 0 && errno == EINTR);
    if (status == 0) {
        return WAIT_RES_TIMEOUT;
    }
    return status < 0 ? WAIT_RES_FAILED : WAIT_RES_READY;
#endif
}

int net_socket_error(sock_t handle) {
    int value = 0;
#ifdef _WIN32
    int length = (int)sizeof(value);
    if (getsockopt(handle, SOL_SOCKET, SO_ERROR, (char *)&value, &length) != 0) {
        return WSAGetLastError();
    }
#else
    socklen_t length = (socklen_t)sizeof(value);
    if (getsockopt(handle, SOL_SOCKET, SO_ERROR, &value, &length) != 0) {
        return errno;
    }
#endif
    return value;
}

ConnectOutcome net_classify(int error) {
#ifdef _WIN32
    if (error == WSAECONNREFUSED) {
        return OUTCOME_CLOSED;
    }
    if (error == WSAETIMEDOUT || error == WSAEHOSTUNREACH || error == WSAENETUNREACH || error == WSAEHOSTDOWN ||
        error == WSAEACCES) {
        return OUTCOME_FILTERED;
    }
#else
    if (error == ECONNREFUSED) {
        return OUTCOME_CLOSED;
    }
    if (error == ETIMEDOUT || error == EHOSTUNREACH || error == ENETUNREACH || error == EHOSTDOWN ||
        error == EACCES || error == EPERM) {
        return OUTCOME_FILTERED;
    }
#endif
    return OUTCOME_ERROR;
}

long net_send(sock_t handle, const char *data, size_t length) {
    return (long)send(handle, data, (int)length, MSG_NOSIGNAL);
}

long net_recv(sock_t handle, unsigned char *buffer, size_t length) {
    return (long)recv(handle, (char *)buffer, (int)length, 0);
}

uint64_t net_now_us(void) {
#ifdef _WIN32
    LARGE_INTEGER frequency;
    LARGE_INTEGER counter;

    QueryPerformanceFrequency(&frequency);
    QueryPerformanceCounter(&counter);
    return (uint64_t)((double)counter.QuadPart * (double)MICROS_PER_SECOND / (double)frequency.QuadPart);
#else
    struct timespec now;

    clock_gettime(CLOCK_MONOTONIC, &now);
    return (uint64_t)now.tv_sec * MICROS_PER_SECOND + (uint64_t)now.tv_nsec / NANOS_PER_MICRO;
#endif
}
