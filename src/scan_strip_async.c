/* Submit single strips to the NPU; the vector kernel hashes and checks tile hits. */
#include <stdint.h>
#include <string.h>

#define R 128
#ifndef K
#define K 4096
#endif

extern void pearl_strip_submit_fast(const int8_t *a);
extern void pearl_strip_wait_done(void);
extern void pearl_set_key_target(const uint32_t *key, const uint32_t *target);
extern void pearl_set_nhi(int n_hi);
extern int pearl_get_hit_result(int *hit_strip, int *hit_tile);

int scan_full(const int8_t *a_noised, int num_strips,
              const uint8_t *key, const uint32_t *target,
              int nbands, int n_hi, int pow_threads,
              uint32_t *scratch, int *hit_strip, int *hit_tile) {
    (void)scratch;
    (void)nbands;
    (void)pow_threads;

    if (num_strips <= 0) return 0;

    uint32_t key_u32[8];
    memcpy(key_u32, key, 32);
    pearl_set_key_target(key_u32, target);
    pearl_set_nhi(n_hi);

    // Prime the pipeline, then submit the next strip before waiting on
    // the oldest one. The underlying kernel owns two in-flight buffer slots.
    pearl_strip_submit_fast(a_noised);
    for (int ss = 0; ss < num_strips; ss++) {
        if (ss + 1 < num_strips)
            pearl_strip_submit_fast(a_noised + (size_t)(ss + 1) * R * K);

        pearl_strip_wait_done();

        int h_strip, h_tile;
        if (pearl_get_hit_result(&h_strip, &h_tile)) {
            *hit_strip = h_strip;
            *hit_tile = h_tile;
            // Drain the already submitted next strip before resetting shared state.
            if (ss + 1 < num_strips) pearl_strip_wait_done();
            return 1;
        }
    }

    return 0;
}
