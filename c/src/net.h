#ifndef NET_H
#define NET_H

#include <stddef.h>
#include <stdint.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
typedef SOCKET sock_t;
typedef int sock_addr_len_t;
typedef int sock_io_len_t;
#define SOCK_INVALID INVALID_SOCKET
#else
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
typedef int sock_t;
typedef socklen_t sock_addr_len_t;
typedef size_t sock_io_len_t;
#define SOCK_INVALID (-1)
#endif

#define ADDRESS_TEXT_MAX 64

typedef struct {
    struct sockaddr_storage storage;
    size_t length;
    int family;
} NetAddress;

typedef enum { WAIT_RES_READY, WAIT_RES_TIMEOUT, WAIT_RES_FAILED } WaitResult;
typedef enum { CONNECT_DONE, CONNECT_PENDING, CONNECT_FAILED } ConnectResult;
typedef enum { OUTCOME_CLOSED, OUTCOME_FILTERED, OUTCOME_ERROR } ConnectOutcome;

int net_init(void);
void net_cleanup(void);

int net_parse_literal(const char *text, NetAddress *out);
int net_resolve(const char *host, NetAddress *out);
int net_format(const NetAddress *address, char *text, size_t text_len);
void net_set_port(NetAddress *address, uint16_t port);
int net_is_local(const NetAddress *address);

sock_t net_open(const NetAddress *address);
void net_close(sock_t handle);
ConnectResult net_connect(sock_t handle, const NetAddress *address, int *error);
WaitResult net_wait(sock_t handle, int for_write, unsigned timeout_ms);
int net_socket_error(sock_t handle);
ConnectOutcome net_classify(int error);
long net_send(sock_t handle, const char *data, size_t length);
long net_recv(sock_t handle, unsigned char *buffer, size_t length);

uint64_t net_now_us(void);

#endif
