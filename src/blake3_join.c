/* BLAKE3 split hook: execute the left subtree on a helper thread when the
 * subtree is large enough and the global thread budget allows it. The right
 * subtree stays on the caller thread, preserving the serial digest.
 */
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <pthread.h>
#include <stdatomic.h>

extern size_t blake3_compress_subtree_wide(const uint8_t *input, size_t input_len,
                                           const uint32_t key[8], uint64_t chunk_counter,
                                           uint8_t flags, uint8_t *out, bool use_tbb);

#ifndef PRL_B3_CAP
#define PRL_B3_CAP 64
#endif
#ifndef PRL_B3_MIN
#define PRL_B3_MIN (1u << 20)
#endif

// This counter only limits helpers; pthread_create/join publish the actual data.
static _Atomic int g_budget = 0;

static int reserve_helper(void) {
    int old = atomic_load_explicit(&g_budget, memory_order_relaxed);
    while (old < PRL_B3_CAP) {
        if (atomic_compare_exchange_weak_explicit(&g_budget, &old, old + 1,
                memory_order_relaxed, memory_order_relaxed))
            return 1;
    }
    return 0;
}

typedef struct {
    const uint8_t *input; size_t input_len; const uint32_t *key;
    uint64_t chunk_counter; uint8_t flags; uint8_t *cvs; size_t *n; bool use_tbb;
} sub_arg;

static void *sub_thread(void *a) {
    sub_arg *s = (sub_arg *)a;
    *s->n = blake3_compress_subtree_wide(s->input, s->input_len, s->key,
                                         s->chunk_counter, s->flags, s->cvs, s->use_tbb);
    return 0;
}

void blake3_compress_subtree_wide_join_tbb(
    const uint32_t key[8], uint8_t flags, bool use_tbb,
    const uint8_t *l_input, size_t l_input_len, uint64_t l_chunk_counter,
    uint8_t *l_cvs, size_t *l_n,
    const uint8_t *r_input, size_t r_input_len, uint64_t r_chunk_counter,
    uint8_t *r_cvs, size_t *r_n)
{
    int spawn = 0;
    if (use_tbb && l_input_len >= PRL_B3_MIN) {
        spawn = reserve_helper();
    }
    // If creating the helper fails, release the reserved budget and run serially.
    if (spawn) {
        sub_arg la = { l_input, l_input_len, key, l_chunk_counter, flags, l_cvs, l_n, use_tbb };
        pthread_t t;
        if (pthread_create(&t, 0, sub_thread, &la) == 0) {
            *r_n = blake3_compress_subtree_wide(r_input, r_input_len, key,
                                                r_chunk_counter, flags, r_cvs, use_tbb);
            pthread_join(t, 0);
            atomic_fetch_sub_explicit(&g_budget, 1, memory_order_relaxed);
            return;
        }
        atomic_fetch_sub_explicit(&g_budget, 1, memory_order_relaxed);
    }
    *l_n = blake3_compress_subtree_wide(l_input, l_input_len, key, l_chunk_counter, flags, l_cvs, use_tbb);
    *r_n = blake3_compress_subtree_wide(r_input, r_input_len, key, r_chunk_counter, flags, r_cvs, use_tbb);
}
