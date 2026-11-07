#ifndef PRL_BLAKE3_NEON4_H
#define PRL_BLAKE3_NEON4_H

/*
 * A-noise only: four independent, keyed, single-block (64-byte) BLAKE3 XOF
 * roots in four AArch64 NEON 32-bit lanes. This is NOT a generic BLAKE3
 * hasher. Every message is LE32(draw + 1) || 28 zero bytes || seed[32].
 * The public API below returns the first 32 bytes of each XOF root.
 *
 * Each lane has independent message word 0; key, seed, and flags are shared.
 * BLAKE3 uses seven rounds and the fixed message permutation. Flags are
 * KEYED_HASH | CHUNK_START | CHUNK_END | ROOT; block_len=64; counter=0.
 * No dynamic dispatch, allocations, or access to other rows.
 */
#if defined(__aarch64__)
#include <arm_neon.h>
#include <stdint.h>

static inline uint32_t prl_b3_4_load32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static inline void prl_b3_4_store32(uint8_t *p, uint32_t w) {
    p[0] = (uint8_t)w;
    p[1] = (uint8_t)(w >> 8);
    p[2] = (uint8_t)(w >> 16);
    p[3] = (uint8_t)(w >> 24);
}

/* Rotate-right is a lane-local 32-bit operation (NOT a cross-lane shift). */
#define PRL_B3_ROR(x, n) vorrq_u32(vshrq_n_u32((x), (n)), vshlq_n_u32((x), 32 - (n)))

static inline __attribute__((always_inline)) void prl_b3_4_g(
        uint32x4_t *a, uint32x4_t *b, uint32x4_t *c, uint32x4_t *d,
        uint32x4_t mx, uint32x4_t my) {
    *a = vaddq_u32(vaddq_u32(*a, *b), mx);
    *d = PRL_B3_ROR(veorq_u32(*d, *a), 16);
    *c = vaddq_u32(*c, *d);
    *b = PRL_B3_ROR(veorq_u32(*b, *c), 12);
    *a = vaddq_u32(vaddq_u32(*a, *b), my);
    *d = PRL_B3_ROR(veorq_u32(*d, *a), 8);
    *c = vaddq_u32(*c, *d);
    *b = PRL_B3_ROR(veorq_u32(*b, *c), 7);
}

/* The 16 selected message vectors for each of BLAKE3's seven rounds are
 * resolved at compile time. Avoid a runtime sigma table and vector gathers. */
#define PRL_B3_ROUND(x0,x1,x2,x3,x4,x5,x6,x7,x8,x9,x10,x11,x12,x13,x14,x15) do { \
    prl_b3_4_g(&v[0], &v[4], &v[8],  &v[12], (x0), (x1)); \
    prl_b3_4_g(&v[1], &v[5], &v[9],  &v[13], (x2), (x3)); \
    prl_b3_4_g(&v[2], &v[6], &v[10], &v[14], (x4), (x5)); \
    prl_b3_4_g(&v[3], &v[7], &v[11], &v[15], (x6), (x7)); \
    prl_b3_4_g(&v[0], &v[5], &v[10], &v[15], (x8), (x9)); \
    prl_b3_4_g(&v[1], &v[6], &v[11], &v[12], (x10), (x11)); \
    prl_b3_4_g(&v[2], &v[7], &v[8],  &v[13], (x12), (x13)); \
    prl_b3_4_g(&v[3], &v[4], &v[9],  &v[14], (x14), (x15)); \
} while (0)

static inline void prl_blake3_a_noise4_neon(
        uint32_t first_draw, const uint8_t seed[32], const uint8_t key[32],
        uint8_t digest[4][32]) {
    static const uint32_t iv[4] = {0x6A09E667u, 0xBB67AE85u,
                                    0x3C6EF372u, 0xA54FF53Au};
    uint32x4_t m[16], v[16];
    uint32_t draw_words[4] = {first_draw + 1u, first_draw + 2u,
                              first_draw + 3u, first_draw + 4u};
    m[0] = vld1q_u32(draw_words);
    for (unsigned j = 1; j < 8; ++j) m[j] = vdupq_n_u32(0);
    for (unsigned j = 0; j < 8; ++j) {
        v[j] = vdupq_n_u32(prl_b3_4_load32(key + j * 4));
        m[j + 8] = vdupq_n_u32(prl_b3_4_load32(seed + j * 4));
    }
    for (unsigned j = 0; j < 4; ++j) v[8 + j] = vdupq_n_u32(iv[j]);
    v[12] = vdupq_n_u32(0);   /* counter low */
    v[13] = vdupq_n_u32(0);   /* counter high */
    v[14] = vdupq_n_u32(64);  /* one full block */
    v[15] = vdupq_n_u32(27);  /* KEYED_HASH | CHUNK_START | CHUNK_END | ROOT */

    PRL_B3_ROUND(m[0], m[1], m[2], m[3], m[4], m[5], m[6], m[7], m[8], m[9], m[10], m[11], m[12], m[13], m[14], m[15]);
    PRL_B3_ROUND(m[2], m[6], m[3], m[10], m[7], m[0], m[4], m[13], m[1], m[11], m[12], m[5], m[9], m[14], m[15], m[8]);
    PRL_B3_ROUND(m[3], m[4], m[10], m[12], m[13], m[2], m[7], m[14], m[6], m[5], m[9], m[0], m[11], m[15], m[8], m[1]);
    PRL_B3_ROUND(m[10], m[7], m[12], m[9], m[14], m[3], m[13], m[15], m[4], m[0], m[11], m[2], m[5], m[8], m[1], m[6]);
    PRL_B3_ROUND(m[12], m[13], m[9], m[11], m[15], m[10], m[14], m[8], m[7], m[2], m[5], m[3], m[0], m[1], m[6], m[4]);
    PRL_B3_ROUND(m[9], m[14], m[11], m[5], m[8], m[12], m[15], m[1], m[13], m[3], m[0], m[10], m[2], m[6], m[4], m[7]);
    PRL_B3_ROUND(m[11], m[15], m[5], m[0], m[1], m[9], m[8], m[6], m[14], m[10], m[2], m[12], m[3], m[4], m[7], m[13]);

    /* XOF bytes 0..31 are v[0..7] ^ v[8..15], not the unmodified CV. */
    uint32_t soa[8][4];
    for (unsigned w = 0; w < 8; ++w)
        vst1q_u32(soa[w], veorq_u32(v[w], v[w + 8]));
    for (unsigned lane = 0; lane < 4; ++lane)
        for (unsigned w = 0; w < 8; ++w)
            prl_b3_4_store32(digest[lane] + w * 4, soa[w][lane]);
}
#undef PRL_B3_ROUND
#undef PRL_B3_ROR
#endif /* __aarch64__ */
#endif /* PRL_BLAKE3_NEON4_H */
