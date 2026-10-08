/* M-batch scan: main thread drives submit/wait on NPU; all BLAKE3 hashing done on NPU.
 * scan_full: reset state, submit strips, wait for completion, return hit result. */
#include <stdint.h>
#include <string.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

#define R 128
#ifndef K
#define K 4096
#endif
#define WORDS 16
#define BN 64
#define MAXT 256
#define MAXSLOT 48

extern void pearl_strip_submit_fast(const int8_t *a);
extern void pearl_strip_wait_done(void);
extern int pearl_mbatch(void);
extern void pearl_set_key_target(const uint32_t *key, const uint32_t *target);
extern void pearl_set_nhi(int n_hi);
extern int pearl_get_hit_result(int *hit_strip, int *hit_tile);

static struct {
    pthread_mutex_t mu;
    int started;
    const uint8_t *key; const uint32_t *target; int nbands, n_hi, G;
    volatile int hit_found; int hit_strip, hit_tile;
} A = { PTHREAD_MUTEX_INITIALIZER };

int scan_full(const int8_t *a_noised, int num_strips,
              const uint8_t *key, const uint32_t *target,
              int nbands, int n_hi, int pow_threads,
              uint32_t *scratch, int *hit_strip, int *hit_tile) {
    (void)scratch;
    (void)pow_threads;

    int G = pearl_mbatch(); if (G < 1) G = 1;
    int n_super = num_strips / G;

    pthread_mutex_lock(&A.mu);
    if (!A.started) A.started = 1;
    A.key = key; A.target = target; A.nbands = nbands; A.n_hi = n_hi; A.G = G;
    A.hit_found = 0; A.hit_strip = A.hit_tile = -1;
    pthread_mutex_unlock(&A.mu);

    uint32_t key_u32[8];
    memcpy(key_u32, key, 32);
    pearl_set_key_target(key_u32, target);
    pearl_set_nhi(n_hi);

    pearl_strip_submit_fast(a_noised);
    for (int ss = 0; ss < n_super; ss++) {
        if (ss + 1 < n_super)
            pearl_strip_submit_fast(a_noised + (size_t)(ss + 1) * G * R * K);

        pearl_strip_wait_done();

        int h_strip, h_tile;
        if (pearl_get_hit_result(&h_strip, &h_tile)) {
            pthread_mutex_lock(&A.mu);
            if (!A.hit_found) {
                A.hit_found = 1;
                A.hit_strip = h_strip;
                A.hit_tile = h_tile;
            }
            pthread_mutex_unlock(&A.mu);
            break;
        }
    }

    pthread_mutex_lock(&A.mu);
    int found = A.hit_found, hs = A.hit_strip, ht = A.hit_tile;
    pthread_mutex_unlock(&A.mu);

    if (found) { *hit_strip = hs; *hit_tile = ht; }
    return found ? 1 : 0;
}
