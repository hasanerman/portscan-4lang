#include "net.h"

#include <string.h>

#ifndef _WIN32
#include <arpa/inet.h>
#endif

#define IPV4_MAPPED_OFFSET 12

int net_init(void) {
#ifdef _WIN32
    WSADATA data;
    return WSAStartup(MAKEWORD(2, 2), &data) == 0;
#else
    return 1;
#endif
}

void net_cleanup(void) {
#ifdef _WIN32
    WSACleanup();
#endif
}

static int is_all_zero(const unsigned char *bytes, size_t length) {
    size_t i;

    for (i = 0; i < length; i++) {
        if (bytes[i] != 0) {
            return 0;
        }
    }
    return 1;
}

static int is_local_v4(const unsigned char *b) {
    return b[0] == 127 || b[0] == 10 || b[0] == 0 || (b[0] == 172 && b[1] >= 16 && b[1] <= 31) ||
           (b[0] == 192 && b[1] == 168) || (b[0] == 169 && b[1] == 254);
}

static int is_local_v6(const unsigned char *b) {
    if (is_all_zero(b, 15) && (b[15] == 0 || b[15] == 1)) {
        return 1;
    }
    if (b[0] == 0xfe && (b[1] & 0xc0) == 0x80) {
        return 1;
    }
    if ((b[0] & 0xfe) == 0xfc) {
        return 1;
    }
    if (is_all_zero(b, 10) && b[10] == 0xff && b[11] == 0xff) {
        return is_local_v4(b + IPV4_MAPPED_OFFSET);
    }
    return 0;
}

int net_is_local(const NetAddress *address) {
    if (address->family == AF_INET) {
        struct sockaddr_in v4;
        memcpy(&v4, &address->storage, sizeof(v4));
        return is_local_v4((const unsigned char *)&v4.sin_addr);
    }
    if (address->family == AF_INET6) {
        struct sockaddr_in6 v6;
        memcpy(&v6, &address->storage, sizeof(v6));
        return is_local_v6((const unsigned char *)&v6.sin6_addr);
    }
    return 0;
}

int net_parse_literal(const char *text, NetAddress *out) {
    struct sockaddr_in v4;
    struct sockaddr_in6 v6;

    memset(out, 0, sizeof(*out));
    memset(&v4, 0, sizeof(v4));
    memset(&v6, 0, sizeof(v6));

    if (inet_pton(AF_INET, text, &v4.sin_addr) == 1) {
        v4.sin_family = AF_INET;
        memcpy(&out->storage, &v4, sizeof(v4));
        out->length = sizeof(v4);
        out->family = AF_INET;
        return 1;
    }
    if (inet_pton(AF_INET6, text, &v6.sin6_addr) == 1) {
        v6.sin6_family = AF_INET6;
        memcpy(&out->storage, &v6, sizeof(v6));
        out->length = sizeof(v6);
        out->family = AF_INET6;
        return 1;
    }
    return 0;
}

static const struct addrinfo *prefer_ipv4(const struct addrinfo *list) {
    const struct addrinfo *item;

    for (item = list; item != NULL; item = item->ai_next) {
        if (item->ai_family == AF_INET) {
            return item;
        }
    }
    return list;
}

int net_resolve(const char *host, NetAddress *out) {
    struct addrinfo hints;
    struct addrinfo *list = NULL;
    const struct addrinfo *chosen;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(host, NULL, &hints, &list) != 0 || list == NULL) {
        return 0;
    }
    chosen = prefer_ipv4(list);
    if ((size_t)chosen->ai_addrlen > sizeof(out->storage)) {
        freeaddrinfo(list);
        return 0;
    }
    memset(out, 0, sizeof(*out));
    memcpy(&out->storage, chosen->ai_addr, (size_t)chosen->ai_addrlen);
    out->length = (size_t)chosen->ai_addrlen;
    out->family = chosen->ai_family;
    freeaddrinfo(list);
    return 1;
}

int net_format(const NetAddress *address, char *text, size_t text_len) {
    if (address->family == AF_INET) {
        struct sockaddr_in v4;
        memcpy(&v4, &address->storage, sizeof(v4));
        return inet_ntop(AF_INET, &v4.sin_addr, text, (sock_addr_len_t)text_len) != NULL;
    }
    if (address->family == AF_INET6) {
        struct sockaddr_in6 v6;
        memcpy(&v6, &address->storage, sizeof(v6));
        return inet_ntop(AF_INET6, &v6.sin6_addr, text, (sock_addr_len_t)text_len) != NULL;
    }
    return 0;
}

void net_set_port(NetAddress *address, uint16_t port) {
    if (address->family == AF_INET) {
        struct sockaddr_in v4;
        memcpy(&v4, &address->storage, sizeof(v4));
        v4.sin_port = htons(port);
        memcpy(&address->storage, &v4, sizeof(v4));
    } else if (address->family == AF_INET6) {
        struct sockaddr_in6 v6;
        memcpy(&v6, &address->storage, sizeof(v6));
        v6.sin6_port = htons(port);
        memcpy(&address->storage, &v6, sizeof(v6));
    }
}
