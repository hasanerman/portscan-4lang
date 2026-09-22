#include "pool.h"

#include <stdlib.h>

#ifdef _WIN32
#include <process.h>
#include <windows.h>
#else
#include <pthread.h>
#endif

#define WORKER_STACK_BYTES (256u * 1024u)

typedef struct {
    size_t task_count;
    PoolTask task;
    void *context;
    volatile long next;
} PoolState;

static long take_next(PoolState *state) {
#ifdef _WIN32
    return InterlockedIncrement(&state->next) - 1;
#else
    return __atomic_fetch_add(&state->next, 1, __ATOMIC_RELAXED);
#endif
}

static void work_loop(PoolState *state) {
    for (;;) {
        long index = take_next(state);

        if (index < 0 || (size_t)index >= state->task_count) {
            return;
        }
        state->task((size_t)index, state->context);
    }
}

static void init_state(PoolState *state, size_t task_count, PoolTask task, void *context) {
    state->task_count = task_count;
    state->task = task;
    state->context = context;
    state->next = 0;
}

#ifdef _WIN32

static unsigned __stdcall worker_entry(void *argument) {
    work_loop((PoolState *)argument);
    return 0;
}

size_t pool_run(size_t task_count, unsigned workers, PoolTask task, void *context) {
    PoolState state;
    HANDLE *handles = (HANDLE *)calloc(workers, sizeof(HANDLE));
    size_t started = 0;
    size_t i;

    init_state(&state, task_count, task, context);
    for (i = 0; handles != NULL && i < workers; i++) {
        uintptr_t handle = _beginthreadex(NULL, WORKER_STACK_BYTES, worker_entry, &state, 0, NULL);
        if (handle == 0) {
            break;
        }
        handles[started++] = (HANDLE)handle;
    }
    if (started == 0) {
        free(handles);
        work_loop(&state);
        return 1;
    }
    for (i = 0; i < started; i++) {
        WaitForSingleObject(handles[i], INFINITE);
        CloseHandle(handles[i]);
    }
    free(handles);
    return started;
}

#else

static void *worker_entry(void *argument) {
    work_loop((PoolState *)argument);
    return NULL;
}

size_t pool_run(size_t task_count, unsigned workers, PoolTask task, void *context) {
    PoolState state;
    pthread_t *threads = (pthread_t *)calloc(workers, sizeof(pthread_t));
    pthread_attr_t attributes;
    size_t started = 0;
    size_t i;

    init_state(&state, task_count, task, context);
    pthread_attr_init(&attributes);
    pthread_attr_setstacksize(&attributes, WORKER_STACK_BYTES);
    for (i = 0; threads != NULL && i < workers; i++) {
        if (pthread_create(&threads[started], &attributes, worker_entry, &state) != 0) {
            break;
        }
        started++;
    }
    pthread_attr_destroy(&attributes);
    if (started == 0) {
        free(threads);
        work_loop(&state);
        return 1;
    }
    for (i = 0; i < started; i++) {
        pthread_join(threads[i], NULL);
    }
    free(threads);
    return started;
}

#endif
