/* Shared host strip queue depth; independent of the cube/vec BUFS ring. */
#ifndef PEARL_PIPELINE_H
#define PEARL_PIPELINE_H
#ifndef PEARL_PIPE_DEPTH
#define PEARL_PIPE_DEPTH 4
#endif
#if PEARL_PIPE_DEPTH < 1
#error "PEARL_PIPE_DEPTH must be positive"
#endif

#include <stdint.h>
#ifndef PEARL_BAND_GROUP
#define PEARL_BAND_GROUP 2
#endif
#if PEARL_BAND_GROUP != 1 && PEARL_BAND_GROUP != 2
#error "PEARL_BAND_GROUP must be 1 or 2"
#endif
/* Each vector block owns one 64-byte region, including an explicit no-hit result.
 * Keep these constants identical in the host and device translation units. */
#define PEARL_GRID 20
#define PEARL_HIT_STRIDE_WORDS 16
#define PEARL_HIT_WORKERS(v) (PEARL_GRID * (v))
#define PEARL_HIT_WORDS(v) (PEARL_HIT_WORKERS(v) * PEARL_HIT_STRIDE_WORDS)

/* Call only after the slot's vector-completion/D2H event has completed. */
static inline int pearl_reduce_hits(const uint32_t *results, int workers,
                                   uint32_t *encoded_tile)
{
    for (int i = 0; i < workers; ++i) {
        const uint32_t *r = results + i * PEARL_HIT_STRIDE_WORDS;
        if (r[1] == 1) {
            *encoded_tile = r[0];
            return 1;
        }
    }
    return 0;
}
#endif
