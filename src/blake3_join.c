/* Persistent, nonblocking BLAKE3 fork/join pool. Busy workers never accept
 * nested work: if no idle slot exists, recursion runs on its caller. This
 * avoids pool starvation/deadlock without changing subtree counters or CVs. */
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <pthread.h>
#include "cpu_budget.h"

extern size_t blake3_compress_subtree_wide(const uint8_t *, size_t,
                                         const uint32_t[8], uint64_t,
                                         uint8_t, uint8_t *, bool);
#ifndef PRL_B3_CAP
#define PRL_B3_CAP 64
#endif
#ifndef PRL_B3_MIN
#define PRL_B3_MIN (1u << 20)
#endif

typedef struct {
    const uint8_t *input; size_t len; const uint32_t *key;
    uint64_t counter; uint8_t flags; uint8_t *cvs; size_t *n; bool parallel;
} sub_arg;
typedef struct {
    pthread_t thread;
    pthread_cond_t ready, done;
    int state; /* 0 idle, 1 queued, 2 running, 3 completed but not reclaimed */
    sub_arg arg;
} worker_t;
static worker_t workers[PRL_B3_CAP];
static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_once_t once = PTHREAD_ONCE_INIT;
static int nworkers, stopping;

static void *run_worker(void *ptr) {
    worker_t *w = ptr;
    pthread_mutex_lock(&mu);
    for (;;) {
        while (w->state != 1 && !stopping) pthread_cond_wait(&w->ready, &mu);
        if (stopping) break;
        sub_arg a = w->arg;
        w->state = 2;
        pthread_mutex_unlock(&mu);
        *a.n = blake3_compress_subtree_wide(a.input, a.len, a.key, a.counter,
                                           a.flags, a.cvs, a.parallel);
        pthread_mutex_lock(&mu);
        w->state = 3;
        pthread_cond_signal(&w->done);
    }
    pthread_mutex_unlock(&mu);
    return 0;
}
/* Call only after prep/proof callers have drained. No active tasks may remain. */
void prl_b3_shutdown(void) {
    pthread_mutex_lock(&mu);
    stopping = 1;
    int n = nworkers;
    for (int i = 0; i < n; ++i) pthread_cond_signal(&workers[i].ready);
    pthread_mutex_unlock(&mu);
    for (int i = 0; i < n; ++i) pthread_join(workers[i].thread, 0);
    pthread_mutex_lock(&mu);
    nworkers = 0;
    pthread_mutex_unlock(&mu);
}
static void init_pool(void) {
    int count = prl_cpu_prep_threads() - 1;
    if (count > PRL_B3_CAP) count = PRL_B3_CAP;
    for (int i = 0; i < count; ++i) {
        worker_t *w = &workers[i];
        if (pthread_cond_init(&w->ready, 0)) break;
        if (pthread_cond_init(&w->done, 0)) {
            pthread_cond_destroy(&w->ready); break;
        }
        if (pthread_create(&w->thread, 0, run_worker, w)) {
            pthread_cond_destroy(&w->ready); pthread_cond_destroy(&w->done); break;
        }
        ++nworkers;
    }
}
void blake3_compress_subtree_wide_join_tbb(
    const uint32_t key[8], uint8_t flags, bool use_tbb,
    const uint8_t *l_input, size_t l_input_len, uint64_t l_chunk_counter,
    uint8_t *l_cvs, size_t *l_n,
    const uint8_t *r_input, size_t r_input_len, uint64_t r_chunk_counter,
    uint8_t *r_cvs, size_t *r_n)
{
    worker_t *w = 0;
    if (use_tbb && l_input_len >= PRL_B3_MIN) {
        pthread_once(&once, init_pool);
        pthread_mutex_lock(&mu);
        if (!stopping) for (int i = 0; i < nworkers; ++i) {
            if (!workers[i].state) {
                w = &workers[i];
                w->arg = (sub_arg){l_input, l_input_len, key, l_chunk_counter,
                                  flags, l_cvs, l_n, use_tbb};
                w->state = 1;
                pthread_cond_signal(&w->ready);
                break;
            }
        }
        pthread_mutex_unlock(&mu);
    }
    if (w) {
        *r_n = blake3_compress_subtree_wide(r_input, r_input_len, key,
                                           r_chunk_counter, flags, r_cvs, use_tbb);
        pthread_mutex_lock(&mu);
        while (w->state != 3) pthread_cond_wait(&w->done, &mu);
        w->state = 0;
        pthread_mutex_unlock(&mu);
        return;
    }
    *l_n = blake3_compress_subtree_wide(l_input, l_input_len, key, l_chunk_counter, flags, l_cvs, use_tbb);
    *r_n = blake3_compress_subtree_wide(r_input, r_input_len, key, r_chunk_counter, flags, r_cvs, use_tbb);
}
