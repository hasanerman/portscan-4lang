#ifndef PORTS_H
#define PORTS_H

#include <stddef.h>
#include <stdint.h>

#define PORT_MIN 1u
#define PORT_MAX 65535u

typedef struct {
    uint16_t *items;
    size_t count;
} PortList;

int ports_parse(const char *spec, PortList *out, char *err, size_t err_len);
void ports_free(PortList *list);

#endif
