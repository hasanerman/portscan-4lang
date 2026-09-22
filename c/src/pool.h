#ifndef POOL_H
#define POOL_H

#include <stddef.h>

typedef void (*PoolTask)(size_t index, void *context);

size_t pool_run(size_t task_count, unsigned workers, PoolTask task, void *context);

#endif
