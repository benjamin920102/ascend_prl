#ifndef PRL_PREP_STATE_H
#define PRL_PREP_STATE_H
#include <stdint.h>
/* Zero-initialize before first use. One state per owned raw matrix allocation.
 * Reset to {0} on free/reallocation or any external write beyond its seed stamp.
 * Never share a state between concurrent writers. Proof readers are unchanged.
 */
typedef struct {
    const int8_t *buffer;
    int64_t size;
    int zero_valid;
} prep_seed_state;
int prep_a_side_cached(uint64_t, int8_t *, const uint8_t *, const uint8_t *,
    int64_t, int64_t, int, int8_t *, int8_t *, uint8_t *, uint8_t *, int, int,
    prep_seed_state *);
int prep_b_side_cached(uint64_t, int8_t *, const uint8_t *, int64_t, int64_t, int,
    int8_t *, int8_t *, uint8_t *, uint8_t *, int, int, prep_seed_state *);
int prep_random_cached(uint64_t, int8_t *, int8_t *, const uint8_t *,
    int64_t, int64_t, int64_t, int, int8_t *, int8_t *, int8_t *, int8_t *,
    uint8_t *, uint8_t *, uint8_t *, uint8_t *, int, int, int,
    prep_seed_state *, prep_seed_state *);
#endif
