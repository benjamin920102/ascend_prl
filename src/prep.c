#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <omp.h>
#include "blake3.h"
#include "blake3_impl.h" /* upstream BLAKE3 compression primitives and flag definitions */
#include "cpu_budget.h"
#include "prl_config.h"

#if defined(__ARM_NEON) || defined(__aarch64__)
#include <arm_neon.h>
#include "prl_blake3_neon4.h"
#define HAVE_NEON 1
#endif

#define DIGEST 32
#define ZERO_POINT 32
#define RANGE_MASK 63

/* Certificate v3 binds each Merkle root to its matrix dimension before deriving
 * noise seeds. These constants must match the A/B domain salts in zk_pow.
 */
static const uint8_t SEED_SALT_A[32] = {
    0x82, 0x49, 0x40, 0x6c, 0xa0, 0xed, 0x15, 0x16, 0x96, 0x16, 0xf6, 0x92, 0xfc, 0xf0, 0x76, 0xf8,
    0x92, 0xdb, 0xdb, 0x2a, 0x70, 0x23, 0xb8, 0x52, 0xf0, 0xd4, 0x77, 0x19, 0xc3, 0x90, 0x01, 0x7b,
};
static const uint8_t SEED_SALT_B[32] = {
    0x11, 0x30, 0x06, 0x32, 0xec, 0x63, 0x01, 0xca, 0x2b, 0xe2, 0xaf, 0x71, 0x8b, 0x3f, 0x4d, 0x4f,
    0x1a, 0xe9, 0xc6, 0x39, 0x88, 0xe8, 0xcc, 0x04, 0x48, 0x44, 0x30, 0x1d, 0x71, 0xb8, 0x9a, 0xa9,
};

static uint32_t prl_load32_le(const uint8_t *p);

/* A single full chunk block is also the root Output. The XOF entry point
 * serializes the root bytes; compress_in_place would instead return a CV. */
static inline void prl_blake3_keyed_64_direct(const uint8_t key[32],
                                             const uint8_t msg[64],
                                             uint8_t out[DIGEST]) {
    uint32_t key_words[8];
    uint8_t xof[64];
    for (unsigned i = 0; i < 8; ++i)
        key_words[i] = prl_load32_le(key + 4 * i);
    blake3_compress_xof(key_words, msg, 64, 0,
                        KEYED_HASH | CHUNK_START | CHUNK_END | ROOT, xof);
    memcpy(out, xof, DIGEST);
}

// Hash a fixed 64-byte block: root || dimension (LE u32) || 28 zero bytes.
static void bind_root(const uint8_t root[32], uint32_t dim, const uint8_t salt[32], uint8_t out[32]) {
    uint8_t msg[64] = {0};
    memcpy(msg, root, 32);
    memcpy(msg + 32, &dim, 4);
    prl_blake3_keyed_64_direct(salt, msg, out);
}

#define CERT_LEGACY 0
#define CERT_SALTED 1

static void salt_roots(int cert_mode, const uint8_t rootA[32], const uint8_t rootB[32],
                        uint32_t m, uint32_t n, uint8_t outA[32], uint8_t outB[32]) {
    if (cert_mode == CERT_SALTED) {
        bind_root(rootA, m, SEED_SALT_A, outA);
        bind_root(rootB, n, SEED_SALT_B, outB);
    } else {
        memcpy(outA, rootA, 32);
        memcpy(outB, rootB, 32);
    }
}

/* Generated A/B matrices are always zero-filled and seed-stamped. Buffers
 * are calloc-owned by miner.c; only bytes 0..7 ever change on reuse.
 * Non-reuse entry points explicitly memset before applying the stamp. */
static inline void stamp_seed(int8_t *buf, int64_t total, uint64_t seed) {
    if (total >= 8) {
        for (int i = 0; i < 8; ++i, seed >>= 8)
            buf[i] = (int8_t)(seed & 0xff);
    }
}

static void draw_hash(uint32_t idx, const uint8_t *seed, const uint8_t *key,
                      int slot, uint8_t out[DIGEST]) {
    uint8_t msg[64] = {0};
    uint32_t v = idx + 1;
    memcpy(msg + slot * 4, &v, 4);
    memcpy(msg + 32, seed, 32);
    prl_blake3_keyed_64_direct(key, msg, out);
}

static void calc_mk(const int8_t *buf, int64_t len, const uint8_t *key, uint8_t *root) {
    blake3_hasher h;
    blake3_hasher_init_keyed(&h, key);
#if defined(BLAKE3_USE_TBB)
    blake3_hasher_update_tbb(&h, buf, (size_t)len);
#else
    blake3_hasher_update(&h, buf, (size_t)len);
#endif
    blake3_hasher_finalize(&h, root, DIGEST);
}

/*
 * Zero-seed Root Hash fast path.
 *
 * The miner's default shape is 16384 x 4096 = 64 MiB (65536 BLAKE3 chunks).
 * We intentionally optimize only that exact full-chunk, power-of-two shape.
 * Every other length/tree shape stays on calc_mk(), including partial final
 * chunks and non-power-of-two chunk counts.
 *
 * Use the same low-level compression entry points as the linked upstream
 * BLAKE3 C implementation. These are internal BLAKE3 C symbols, already
 * linked by this project (blake3_join.c uses the same internal API family).
 */
#define PRL_B3_BLOCK_LEN       64u
#define PRL_B3_CHUNK_LEN       1024u
#define PRL_B3_KEYED_HASH      KEYED_HASH
#define PRL_B3_CHUNK_START     CHUNK_START
#define PRL_B3_CHUNK_END       CHUNK_END
#define PRL_B3_PARENT          PARENT
#define PRL_B3_ROOT            ROOT
#define ZERO_SEED_CHUNK_COUNT   UINT64_C(65536)
#define ZERO_SEED_CACHE_LEVELS  16u
#define ZERO_SEED_PREFIX_LEN     8u
#define ZERO_SEED_MATRIX_BYTES  ((size_t)ZERO_SEED_CHUNK_COUNT * PRL_B3_CHUNK_LEN)

typedef struct {
    uint8_t key[32];
    size_t matrix_len;
    uint64_t chunk_count;
    uint8_t prefix_len;
    uint8_t hash_flags;
    uint8_t sibling_cv[ZERO_SEED_CACHE_LEVELS][DIGEST];
    int valid;
} zero_seed_cache_t;

/* Cache data is immutable while a reader holds the read lock. A write lock is
 * taken only on a cache miss/key change; readers copy the 512-byte CV ladder
 * before releasing the lock, so later replacement cannot race with hashing. */
static zero_seed_cache_t g_zero_seed_cache;
static pthread_rwlock_t g_zero_seed_cache_lock = PTHREAD_RWLOCK_INITIALIZER;

static uint32_t prl_load32_le(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void prl_store32_le(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static void zero_chunk_cv(uint64_t chunk_counter, const uint32_t key_words[8],
                          const uint8_t *prefix, size_t prefix_len,
                          uint8_t out_cv[DIGEST]) {
    uint32_t cv[8];
    uint8_t block[PRL_B3_BLOCK_LEN];
    memcpy(cv, key_words, sizeof(cv));

    for (unsigned block_index = 0; block_index < PRL_B3_CHUNK_LEN / PRL_B3_BLOCK_LEN; ++block_index) {
        memset(block, 0, sizeof(block));
        if (block_index == 0 && prefix && prefix_len) {
            size_t n = prefix_len < sizeof(block) ? prefix_len : sizeof(block);
            memcpy(block, prefix, n);
        }
        uint8_t flags = PRL_B3_KEYED_HASH;
        if (block_index == 0) flags |= PRL_B3_CHUNK_START;
        if (block_index + 1 == PRL_B3_CHUNK_LEN / PRL_B3_BLOCK_LEN)
            flags |= PRL_B3_CHUNK_END;
        /* BLAKE3 keeps the chunk counter constant across all 16 blocks. */
        blake3_compress_in_place(cv, block, PRL_B3_BLOCK_LEN, chunk_counter, flags);
    }

    for (unsigned i = 0; i < 8; ++i) prl_store32_le(out_cv + i * 4, cv[i]);
}

static void zero_parent_cv(const uint8_t left_cv[DIGEST], const uint8_t right_cv[DIGEST],
                           const uint32_t key_words[8], uint8_t out_cv[DIGEST]) {
    uint8_t block[PRL_B3_BLOCK_LEN];
    uint32_t cv[8];
    memcpy(block, left_cv, DIGEST);
    memcpy(block + DIGEST, right_cv, DIGEST);
    memcpy(cv, key_words, sizeof(cv));
    blake3_compress_in_place(cv, block, PRL_B3_BLOCK_LEN, 0,
                             PRL_B3_KEYED_HASH | PRL_B3_PARENT);
    for (unsigned i = 0; i < 8; ++i) prl_store32_le(out_cv + i * 4, cv[i]);
}

static void zero_root_finalize(const uint8_t left_cv[DIGEST], const uint8_t right_cv[DIGEST],
                               const uint32_t key_words[8], uint8_t root[DIGEST]) {
    uint8_t block[PRL_B3_BLOCK_LEN], output[64];
    memcpy(block, left_cv, DIGEST);
    memcpy(block + DIGEST, right_cv, DIGEST);
    /* Root is an Output operation, not a raw parent chaining value. */
    blake3_compress_xof(key_words, block, PRL_B3_BLOCK_LEN, 0,
                        PRL_B3_KEYED_HASH | PRL_B3_PARENT | PRL_B3_ROOT, output);
    memcpy(root, output, DIGEST);
}

/* Compute a complete, aligned, power-of-two subtree of all-zero chunks. */
static void zero_subtree_cv(uint64_t first_chunk, unsigned level,
                            const uint32_t key_words[8], uint8_t out_cv[DIGEST]) {
    if (level == 0) {
        zero_chunk_cv(first_chunk, key_words, NULL, 0, out_cv);
        return;
    }
    uint8_t left_cv[DIGEST], right_cv[DIGEST];
    uint64_t half = UINT64_C(1) << (level - 1);
    zero_subtree_cv(first_chunk, level - 1, key_words, left_cv);
    zero_subtree_cv(first_chunk + half, level - 1, key_words, right_cv);
    zero_parent_cv(left_cv, right_cv, key_words, out_cv);
}

static int zero_seed_cache_matches(const uint8_t key[32], size_t matrix_len,
                                   uint64_t chunk_count, uint8_t prefix_len,
                                   uint8_t hash_flags) {
    return g_zero_seed_cache.valid &&
           g_zero_seed_cache.matrix_len == matrix_len &&
           g_zero_seed_cache.chunk_count == chunk_count &&
           g_zero_seed_cache.prefix_len == prefix_len &&
           g_zero_seed_cache.hash_flags == hash_flags &&
           memcmp(g_zero_seed_cache.key, key, 32) == 0;
}

static void zero_seed_cache_snapshot(const uint8_t key[32],
                                     uint8_t sibling_cv[ZERO_SEED_CACHE_LEVELS][DIGEST]) {
    const size_t matrix_len = ZERO_SEED_MATRIX_BYTES;
    const uint64_t chunk_count = ZERO_SEED_CHUNK_COUNT;
    const uint8_t prefix_len = ZERO_SEED_PREFIX_LEN;
    const uint8_t hash_flags = PRL_B3_KEYED_HASH;

    pthread_rwlock_rdlock(&g_zero_seed_cache_lock);
    if (zero_seed_cache_matches(key, matrix_len, chunk_count, prefix_len, hash_flags)) {
        memcpy(sibling_cv, g_zero_seed_cache.sibling_cv, sizeof(g_zero_seed_cache.sibling_cv));
        pthread_rwlock_unlock(&g_zero_seed_cache_lock);
        return;
    }
    pthread_rwlock_unlock(&g_zero_seed_cache_lock);

    pthread_rwlock_wrlock(&g_zero_seed_cache_lock);
    if (!zero_seed_cache_matches(key, matrix_len, chunk_count, prefix_len, hash_flags)) {
        uint32_t key_words[8];
        uint8_t built[ZERO_SEED_CACHE_LEVELS][DIGEST];
        for (unsigned i = 0; i < 8; ++i) key_words[i] = prl_load32_le(key + i * 4);

        /* Right siblings of chunk 0: [1], [2..3], ... [32768..65535].
         * Each zero leaf is hashed once; only the 16 subtree roots survive. */
        for (unsigned level = 0; level < ZERO_SEED_CACHE_LEVELS; ++level) {
            uint64_t first_chunk = UINT64_C(1) << level;
            zero_subtree_cv(first_chunk, level, key_words, built[level]);
        }

        g_zero_seed_cache.valid = 0;
        memcpy(g_zero_seed_cache.key, key, 32);
        g_zero_seed_cache.matrix_len = matrix_len;
        g_zero_seed_cache.chunk_count = chunk_count;
        g_zero_seed_cache.prefix_len = prefix_len;
        g_zero_seed_cache.hash_flags = hash_flags;
        memcpy(g_zero_seed_cache.sibling_cv, built, sizeof(built));
        g_zero_seed_cache.valid = 1;
    }
    memcpy(sibling_cv, g_zero_seed_cache.sibling_cv, sizeof(g_zero_seed_cache.sibling_cv));
    pthread_rwlock_unlock(&g_zero_seed_cache_lock);
}

/* Returns 1 only when the exact 64 MiB / 65536-chunk shape was optimized.
 * The caller guarantees zero-filled, seed-stamped storage; this
 * function deliberately reads only the 8-byte stamp and never scans the tail. */
static int calc_mk_zero_seed_cached(const int8_t *buf, int64_t len,
                                    const uint8_t *key, uint8_t *root) {
    if (!buf || !key || !root || len != (int64_t)ZERO_SEED_MATRIX_BYTES)
        return 0;

    uint8_t siblings[ZERO_SEED_CACHE_LEVELS][DIGEST];
    uint32_t key_words[8];
    uint8_t current[DIGEST], next[DIGEST];
    for (unsigned i = 0; i < 8; ++i) key_words[i] = prl_load32_le(key + i * 4);

    zero_seed_cache_snapshot(key, siblings);
    zero_chunk_cv(0, key_words, (const uint8_t *)buf, ZERO_SEED_PREFIX_LEN, current);

    /* Merge chunk 0 with each cached right sibling in BLAKE3's left/right order.
     * The final level must emit ROOT output, not merely a parent CV. */
    for (unsigned level = 0; level + 1 < ZERO_SEED_CACHE_LEVELS; ++level) {
        zero_parent_cv(current, siblings[level], key_words, next);
        memcpy(current, next, DIGEST);
    }
    zero_root_finalize(current, siblings[ZERO_SEED_CACHE_LEVELS - 1], key_words, root);
    return 1;
}

static void calc_mk_seed_stamp(const int8_t *buf, int64_t len, const uint8_t *key,
                                uint8_t *root) {
    if (calc_mk_zero_seed_cached(buf, len, key, root)) return;
    calc_mk(buf, len, key, root);
}

/* n is at most DIGEST; all transformed values lie in [-32, 31]. */
static inline void noise_digest_store(const uint8_t d[DIGEST], int8_t *out, int64_t n) {
#ifdef HAVE_NEON
    if (n == DIGEST) {
        uint8x16_t mask = vdupq_n_u8(RANGE_MASK);
        int8x16_t zero = vdupq_n_s8(ZERO_POINT);
        uint8x16_t lo = vandq_u8(vld1q_u8(d), mask);
        uint8x16_t hi = vandq_u8(vld1q_u8(d + 16), mask);
        vst1q_s8(out, vsubq_s8(vreinterpretq_s8_u8(lo), zero));
        vst1q_s8(out + 16, vsubq_s8(vreinterpretq_s8_u8(hi), zero));
        return;
    }
#endif
    for (int64_t j = 0; j < n; ++j)
        out[j] = (int8_t)((d[j] & RANGE_MASK) - ZERO_POINT);
}

static void unif_int8(const uint8_t *seed, const uint8_t *key, int64_t nbytes, int8_t *out, int nt) {
    int64_t draws = (nbytes + DIGEST - 1) / DIGEST;

#pragma omp parallel for schedule(static) num_threads(nt)
    for (int64_t i = 0; i < draws; i++) {
        uint8_t d[DIGEST];
        draw_hash((uint32_t)i, seed, key, 0, d);
        int64_t off = i * DIGEST, n = nbytes - off;
        if (n > DIGEST) n = DIGEST;
        noise_digest_store(d, out + off, n);
    }
}

// Each index pair is deterministically derived from the commitment; XOR ensures
// the second rank index differs from the first without a rejection loop.
static void perm_pairs(const uint8_t *seed, const uint8_t *key, int64_t lines,
                       uint16_t *first, uint16_t *second) {
    const int64_t draws = (lines * 4 + DIGEST - 1) / DIGEST;
    for (int64_t i = 0; i < draws; ++i) {
        uint8_t d[DIGEST];
        draw_hash((uint32_t)i, seed, key, 1, d);
        for (int j = 0; j < 8; ++j) {
            int64_t line = i * 8 + j;
            if (line >= lines) break;
            uint32_t u;
            memcpy(&u, d + j * 4, 4);
            uint32_t f = u & (PRL_RANK - 1);
            uint32_t partner = f ^ (1u + (uint32_t)(((uint64_t)(PRL_RANK - 1) * u) >> 32));
            first[line] = (uint16_t)f;
            second[line] = (uint16_t)partner;
        }
    }
}

#if defined(__aarch64__)
static void perm_pairs_u8(const uint8_t *seed, const uint8_t *key, int64_t lines,
                          uint8_t *first, uint8_t *second) {
    const int64_t draws = (lines * 4 + DIGEST - 1) / DIGEST;
    for (int64_t i = 0; i < draws; ++i) {
        uint8_t d[DIGEST];
        draw_hash((uint32_t)i, seed, key, 1, d);
        for (int j = 0; j < 8; ++j) {
            int64_t line = i * 8 + j;
            if (line >= lines) break;
            uint32_t u;
            memcpy(&u, d + j * 4, 4);
            uint32_t f = u & (PRL_RANK - 1);
            uint32_t partner = f ^ (1u + (uint32_t)(((uint64_t)(PRL_RANK - 1) * u) >> 32));
            first[line] = (uint8_t)f;
            second[line] = (uint8_t)partner;
        }
    }
}
#endif

/* AArch64 TBL gathers 16 noise values directly from register tables.
 * The original uint16_t entry point remains available for B and fallback;
 * fused A uses byte indices directly (all rank-128 indices are < 128).
 * Two disjoint 64-byte lookups return zero outside their respective ranges.
 */
#if defined(__aarch64__)
typedef struct { int8x16x4_t lo, hi; } noise128_t;

static inline noise128_t noise128_load(const int8_t *e) {
    noise128_t t;
    for (int i = 0; i < 4; ++i) {
        t.lo.val[i] = vld1q_s8(e + i * 16);
        t.hi.val[i] = vld1q_s8(e + 64 + i * 16);
    }
    return t;
}

static inline uint8x16_t indices16(const uint16_t *p) {
    return vcombine_u8(vmovn_u16(vld1q_u16(p)),
                       vmovn_u16(vld1q_u16(p + 8)));
}

static inline int8x16_t noise128_gather(noise128_t t, uint8x16_t idx) {
    return vorrq_s8(vqtbl4q_s8(t.lo, idx),
                    vqtbl4q_s8(t.hi, vsubq_u8(idx, vdupq_n_u8(64))));
}

static inline void noise128_apply(noise128_t t, const int8_t *src, int8_t *dst,
                                  const uint16_t *f, const uint16_t *s,
                                  int64_t count) {
    int64_t j = 0;
    for (; j + 16 <= count; j += 16) {
        int8x16_t vf = noise128_gather(t, indices16(f + j));
        int8x16_t vs = noise128_gather(t, indices16(s + j));
        /* Non-saturating arithmetic preserves the original int8_t wrap. */
        vst1q_s8(dst + j, vsubq_s8(vaddq_s8(src ? vld1q_s8(src + j) : vdupq_n_s8(0), vf), vs));
    }
    /* Callers use multiples of 16; retain a correct tail for other shapes. */
    for (; j < count; ++j) {
        uint8x16_t fi = vdupq_n_u8((uint8_t)f[j]);
        uint8x16_t si = vdupq_n_u8((uint8_t)s[j]);
        dst[j] = (int8_t)((src ? src[j] : 0) + vgetq_lane_s8(noise128_gather(t, fi), 0)
                                 - vgetq_lane_s8(noise128_gather(t, si), 0));
    }
}

static inline void noise128_apply_u8(noise128_t t, const int8_t *src, int8_t *dst,
                                     const uint8_t *f, const uint8_t *s,
                                     int64_t count) {
    int64_t j = 0;
    for (; j + 16 <= count; j += 16) {
        int8x16_t vf = noise128_gather(t, vld1q_u8(f + j));
        int8x16_t vs = noise128_gather(t, vld1q_u8(s + j));
        int8x16_t va = src ? vld1q_s8(src + j) : vdupq_n_s8(0);
        vst1q_s8(dst + j, vsubq_s8(vaddq_s8(va, vf), vs));
    }
    for (; j < count; ++j) {
        int value = (src ? src[j] : 0)
                  + vgetq_lane_s8(noise128_gather(t, vdupq_n_u8(f[j])), 0)
                  - vgetq_lane_s8(noise128_gather(t, vdupq_n_u8(s[j])), 0);
        /* Store the low byte through a character type: explicit modulo 256,
         * without out-of-range signed conversion or pointer reinterpretation. */
        ((unsigned char *)dst)[j] = (unsigned char)value;
    }
}

/* For generated A, read only noise. The original A is all zero except the
 * eight seed-stamp bytes, added once after the OpenMP worker barrier. */
static void compute_an128_fused_stamp(const int8_t *A, const uint8_t *seed,
                                const uint8_t *key, int8_t *EAL, int8_t *out,
                                const uint8_t *f, const uint8_t *s,
                                int64_t m, int64_t k, int nt) {
#pragma omp parallel for schedule(static) num_threads(nt)
    for (int64_t r = 0; r < m; ++r) {
        int8_t row[PRL_RANK];
        /* Four independent BLAKE3 keyed roots, one per NEON 32-bit lane.
         * Exact message order is draw=4*r+q; output remains 4*32 bytes. */
        uint8_t digests[4][DIGEST];
        prl_blake3_a_noise4_neon((uint32_t)(4 * (uint64_t)r), seed, key, digests);
        for (unsigned q = 0; q < 4; ++q)
            noise_digest_store(digests[q], row + q * DIGEST, DIGEST);
        memcpy(EAL + r * PRL_RANK, row, sizeof(row));
        noise128_apply_u8(noise128_load(row), NULL, out + r * k, f, s, k);
    }
    if (m * k >= 8)
        for (int i = 0; i < 8; ++i)
            ((uint8_t *)out)[i] = (uint8_t)((int)out[i] + A[i]);
}

/* External prep_from_ab() supports arbitrary input matrices (not zero-filled). */
static void compute_an128_fused_raw(const int8_t *A, const uint8_t *seed,
                                const uint8_t *key, int8_t *EAL, int8_t *out,
                                const uint8_t *f, const uint8_t *s,
                                int64_t m, int64_t k, int nt) {
#pragma omp parallel for schedule(static) num_threads(nt)
    for (int64_t r = 0; r < m; ++r) {
        int8_t row[PRL_RANK];
        /* Four independent BLAKE3 keyed roots, one per NEON 32-bit lane.
         * Exact message order is draw=4*r+q; output remains 4*32 bytes. */
        uint8_t digests[4][DIGEST];
        prl_blake3_a_noise4_neon((uint32_t)(4 * (uint64_t)r), seed, key, digests);
        for (unsigned q = 0; q < 4; ++q)
            noise_digest_store(digests[q], row + q * DIGEST, DIGEST);
        memcpy(EAL + r * PRL_RANK, row, sizeof(row));
        noise128_apply_u8(noise128_load(row), A + r * k, out + r * k, f, s, k);
    }
}
#endif

static void compute_an_stamp(const int8_t *A, const int8_t *EAL, int8_t *out,
                       const uint16_t *f, const uint16_t *s,
                       int64_t m, int64_t k, int nt) {
#pragma omp parallel for schedule(static) num_threads(nt)
    for (int64_t r = 0; r < m; ++r) {
        const int8_t *el = EAL + r * PRL_RANK;
        int8_t *o = out + r * k;
        for (int64_t j = 0; j < k; ++j)
            o[j] = (int8_t)(el[f[j]] - el[s[j]]);
    }
    if (m * k >= 8)
        for (int i = 0; i < 8; ++i)
            ((uint8_t *)out)[i] = (uint8_t)((int)out[i] + A[i]);
}

static void compute_an_raw(const int8_t *A, const int8_t *EAL, int8_t *out,
                       const uint16_t *f, const uint16_t *s,
                       int64_t m, int64_t k, int nt) {
#pragma omp parallel for schedule(static) num_threads(nt)
    for (int64_t r = 0; r < m; ++r) {
        const int8_t *ar = A + r * k;
        const int8_t *el = EAL + r * PRL_RANK;
        int8_t *o = out + r * k;
        for (int64_t j = 0; j < k; ++j)
            o[j] = (int8_t)(ar[j] + el[f[j]] - el[s[j]]);
    }
}

/* Each entry point has one static, rank-128 algorithm, no runtime rank check. */
static int prepare_an_stamp(const int8_t *A, const uint8_t *seed, const uint8_t *key,
                       int8_t *EAL, int8_t *out, int64_t m, int64_t k, int nt) {
#if defined(__aarch64__)
    uint8_t *pairs = malloc((size_t)k * 2);
    if (!pairs) return -3;
    perm_pairs_u8(seed, key, k, pairs, pairs + k);
    compute_an128_fused_stamp(A, seed, key, EAL, out, pairs, pairs + k, m, k, nt);
#else
    uint16_t *pairs = malloc((size_t)k * 2 * sizeof(*pairs));
    if (!pairs) return -3;
    perm_pairs(seed, key, k, pairs, pairs + k);
    unif_int8(seed, key, m * PRL_RANK, EAL, nt);
    compute_an_stamp(A, EAL, out, pairs, pairs + k, m, k, nt);
#endif
    free(pairs);
    return 0;
}

static int prepare_an_raw(const int8_t *A, const uint8_t *seed, const uint8_t *key,
                       int8_t *EAL, int8_t *out, int64_t m, int64_t k, int nt) {
#if defined(__aarch64__)
    uint8_t *pairs = malloc((size_t)k * 2);
    if (!pairs) return -3;
    perm_pairs_u8(seed, key, k, pairs, pairs + k);
    compute_an128_fused_raw(A, seed, key, EAL, out, pairs, pairs + k, m, k, nt);
#else
    uint16_t *pairs = malloc((size_t)k * 2 * sizeof(*pairs));
    if (!pairs) return -3;
    perm_pairs(seed, key, k, pairs, pairs + k);
    unif_int8(seed, key, m * PRL_RANK, EAL, nt);
    compute_an_raw(A, EAL, out, pairs, pairs + k, m, k, nt);
#endif
    free(pairs);
    return 0;
}

#define TB 64
static void compute_bn(const int8_t *B, const int8_t *EBR, int8_t *out,
                       const uint16_t *f, const uint16_t *s,
                       int64_t k, int64_t n, int nt) {
    int64_t kb = (k + TB - 1) / TB;
#pragma omp parallel for schedule(static) num_threads(nt)
    for (int64_t ib = 0; ib < kb; ib++) {
        int64_t i0 = ib * TB, ni = k - i0 < TB ? k - i0 : TB;
        int8_t tile[TB][TB];
        for (int64_t j0 = 0; j0 < n; j0 += TB) {
            int64_t nj = n - j0 < TB ? n - j0 : TB;
            for (int64_t j = 0; j < nj; ++j) {
                const int8_t *bj = B + (j0 + j) * k + i0;
                const int8_t *ej = EBR + (j0 + j) * PRL_RANK;
#if defined(__aarch64__)
                noise128_apply(noise128_load(ej), bj, tile[j], f + i0, s + i0, ni);
#else
                for (int64_t i = 0; i < ni; ++i)
                    tile[j][i] = (int8_t)(bj[i] + ej[f[i0 + i]] - ej[s[i0 + i]]);
#endif
            }
            /* Transpose in a bounded per-thread tile; GM stores now follow
             * adjacent columns instead of repeatedly writing n bytes apart. */
            for (int64_t i = 0; i < ni; ++i) {
                int8_t *dst = out + (i0 + i) * n + j0;
                for (int64_t j = 0; j < nj; ++j) dst[j] = tile[j][i];
            }
        }
    }
}

#define BN_PACK 64
// Pack the noised B matrix by 64-column band and rank-sized fold, matching the
// NPU cube kernel's [band][fold][column][k] access order.
static void compute_bn_pack(const int8_t *B, const int8_t *EBR, int8_t *bt,
                            const uint16_t *f, const uint16_t *s,
                            int64_t k, int64_t n, int nt) {
    int64_t nbands = n / BN_PACK, NFOLD = k / PRL_RANK;
#pragma omp parallel for schedule(static) num_threads(nt)
    for (int64_t jp = 0; jp < nbands; jp++) {
        /* One column at a time reuses its noise row across all folds and
         * reads its source B column sequentially. The packed offset is unchanged. */
        for (int64_t col_in_band = 0; col_in_band < BN_PACK; col_in_band++) {
            int64_t col = jp * BN_PACK + col_in_band;
            const int8_t *bcol = B + col * k;
            const int8_t *ecol = EBR + col * PRL_RANK;
#if defined(__aarch64__)
            noise128_t t = noise128_load(ecol);
            for (int64_t p = 0; p < NFOLD; ++p) {
                int64_t row = p * PRL_RANK;
                int8_t *dst = bt + ((jp * NFOLD + p) * BN_PACK + col_in_band) * PRL_RANK;
                noise128_apply(t, bcol + row, dst, f + row, s + row, PRL_RANK);
            }
#else
            for (int64_t p = 0; p < NFOLD; ++p) {
                int8_t *dst = bt + ((jp * NFOLD + p) * BN_PACK + col_in_band) * PRL_RANK;
                for (int64_t ki = 0; ki < PRL_RANK; ++ki) {
                    int64_t row = p * PRL_RANK + ki;
                    dst[ki] = (int8_t)(bcol[row] + ecol[f[row]] - ecol[s[row]]);
                }
            }
#endif
        }
    }
}

static int prep_from_ab_impl(const int8_t *A, const int8_t *B, const uint8_t *key,
                 int64_t m, int64_t n, int64_t k,
                 int8_t *A_noised, int8_t *Bt_out,
                 int8_t *EAL, int8_t *EBR,
                 uint8_t *rootA, uint8_t *rootB,
                 uint8_t *commitA, uint8_t *commitB,
                 int nt, int pack, int cert_mode) {
    if (nt < 1 || nt > prl_cpu_prep_threads()) nt = prl_cpu_prep_threads();
    if ((m * k) % 1024 || (n * k) % 1024) return -1;

    /* The persistent hash team already fills the prep partition. Avoid two
     * independent root callers competing for that same helper budget. */
    calc_mk_seed_stamp(A, m * k, key, rootA);
    calc_mk_seed_stamp(B, n * k, key, rootB);

    uint8_t saltedA[32], saltedB[32];
    salt_roots(cert_mode, rootA, rootB, (uint32_t)m, (uint32_t)n, saltedA, saltedB);

    // B commits first; A commits to B, so the two noise seeds are linked.
    blake3_hasher h;
    blake3_hasher_init(&h); blake3_hasher_update(&h, key, 32);
    blake3_hasher_update(&h, saltedB, 32); blake3_hasher_finalize(&h, commitB, 32);
    blake3_hasher_init(&h); blake3_hasher_update(&h, commitB, 32);
    blake3_hasher_update(&h, saltedA, 32); blake3_hasher_finalize(&h, commitA, 32);

    static const uint8_t seedA[32] = "A_tensor", seedB[32] = "B_tensor";
    unif_int8(seedB, commitB, n * PRL_RANK, EBR, nt);

    if (k > (1 << 16)) return -2;
    uint16_t *pairs = malloc((size_t)k * 2 * sizeof(*pairs));
    if (!pairs) return -3;
    uint16_t *fB = pairs, *sB = fB + k;
    perm_pairs(seedB, commitB, k, fB, sB);

    int rc = prepare_an_stamp(A, seedA, commitA, EAL, A_noised, m, k, nt);
    if (rc) { free(pairs); return rc; }
    if (pack) {
        compute_bn_pack(B, EBR, Bt_out, fB, sB, k, n, nt);
    } else {
        compute_bn(B, EBR, Bt_out, fB, sB, k, n, nt);
    }
    free(pairs);
    return 0;
}

/* Generic external input preserves arbitrary matrices. The production miner
 * never calls this entry point; only generated matrices get stamp fast paths. */
int prep_from_ab(const int8_t *A, const int8_t *B, const uint8_t *key,
                 int64_t m, int64_t n, int64_t k,
                 int8_t *A_noised, int8_t *Bt_noised, int8_t *EAL, int8_t *EBR,
                 uint8_t *rootA, uint8_t *rootB, uint8_t *commitA, uint8_t *commitB,
                 int nt, int cert_version) {
    if (nt < 1 || nt > prl_cpu_prep_threads()) nt = prl_cpu_prep_threads();
    if ((m * k) % 1024 || (n * k) % 1024) return -1;
    if (k > (1 << 16)) return -2;
    calc_mk(A, m * k, key, rootA);
    calc_mk(B, n * k, key, rootB);
    uint8_t saltedA[32], saltedB[32];
    salt_roots(cert_version >= 3 ? CERT_SALTED : CERT_LEGACY,
               rootA, rootB, (uint32_t)m, (uint32_t)n, saltedA, saltedB);
    blake3_hasher h;
    blake3_hasher_init(&h); blake3_hasher_update(&h, key, 32);
    blake3_hasher_update(&h, saltedB, 32); blake3_hasher_finalize(&h, commitB, 32);
    blake3_hasher_init(&h); blake3_hasher_update(&h, commitB, 32);
    blake3_hasher_update(&h, saltedA, 32); blake3_hasher_finalize(&h, commitA, 32);
    static const uint8_t seedA[32] = "A_tensor", seedB[32] = "B_tensor";
    unif_int8(seedB, commitB, n * PRL_RANK, EBR, nt);
    uint16_t *pairs = malloc((size_t)k * 2 * sizeof(*pairs));
    if (!pairs) return -3;
    perm_pairs(seedB, commitB, k, pairs, pairs + k);
    int rc = prepare_an_raw(A, seedA, commitA, EAL, A_noised, m, k, nt);
    if (!rc) compute_bn(B, EBR, Bt_noised, pairs, pairs + k, k, n, nt);
    free(pairs);
    return rc;
}

static int prep_random_impl(uint64_t seed, int8_t *A, int8_t *B, const uint8_t *key,
                            int64_t m, int64_t n, int64_t k,
                            int8_t *A_noised, int8_t *Bt_out, int8_t *EAL, int8_t *EBR,
                            uint8_t *rootA, uint8_t *rootB, uint8_t *commitA, uint8_t *commitB,
                            int nt, int pack, int cert_mode) {
    if (nt < 1 || nt > prl_cpu_prep_threads()) nt = prl_cpu_prep_threads();
    stamp_seed(A, m * k, seed);
    stamp_seed(B, n * k, seed ^ 0xB0B0B0B0ULL);
    return prep_from_ab_impl(A, B, key, m, n, k, A_noised, Bt_out,
                             EAL, EBR, rootA, rootB, commitA, commitB, nt, pack,
                             cert_mode);
}

int prep_random(uint64_t seed, int8_t *A, int8_t *B, const uint8_t *key,
                int64_t m, int64_t n, int64_t k,
                int8_t *A_noised, int8_t *Bt_noised, int8_t *EAL, int8_t *EBR,
                uint8_t *rootA, uint8_t *rootB, uint8_t *commitA, uint8_t *commitB,
                int nt, int cert_version) {
    memset(A, 0, (size_t)(m * k));
    memset(B, 0, (size_t)(n * k));

    int cert_mode = cert_version >= 3 ? CERT_SALTED : CERT_LEGACY;
    return prep_random_impl(seed, A, B, key, m, n, k, A_noised, Bt_noised,
                            EAL, EBR, rootA, rootB, commitA, commitB, nt, 0, cert_mode);
}

int prep_random_bt(uint64_t seed, int8_t *A, int8_t *B, const uint8_t *key,
                int64_t m, int64_t n, int64_t k,
                int8_t *A_noised, int8_t *bt_packed, int8_t *EAL, int8_t *EBR,
                uint8_t *rootA, uint8_t *rootB, uint8_t *commitA, uint8_t *commitB,
                int nt, int cert_version) {
    memset(A, 0, (size_t)(m * k));
    memset(B, 0, (size_t)(n * k));

    int cert_mode = cert_version >= 3 ? CERT_SALTED : CERT_LEGACY;
    return prep_random_impl(seed, A, B, key, m, n, k, A_noised, bt_packed,
                            EAL, EBR, rootA, rootB, commitA, commitB, nt, 1, cert_mode);
}

static int prep_b_side_impl(uint64_t seed, int8_t *B, const uint8_t *key,
                int64_t n, int64_t k,
                int8_t *bt_packed, int8_t *EBR, uint8_t *rootB, uint8_t *commitB,
                int nt, int cert_version) {
    if (nt < 1 || nt > prl_cpu_prep_threads()) nt = prl_cpu_prep_threads();
    if ((n * k) % 1024) return -1;
    if (k > (1 << 16)) return -2;

    stamp_seed(B, n * k, seed);
    calc_mk_seed_stamp(B, n * k, key, rootB);

    int cert_mode = cert_version >= 3 ? CERT_SALTED : CERT_LEGACY;
    uint8_t saltedB[32];
    if (cert_mode == CERT_SALTED) bind_root(rootB, (uint32_t)n, SEED_SALT_B, saltedB);
    else memcpy(saltedB, rootB, 32);

    blake3_hasher h;
    blake3_hasher_init(&h); blake3_hasher_update(&h, key, 32);
    blake3_hasher_update(&h, saltedB, 32); blake3_hasher_finalize(&h, commitB, 32);

    static const uint8_t seedB[32] = "B_tensor";
    unif_int8(seedB, commitB, n * PRL_RANK, EBR, nt);

    uint16_t *fB = malloc((size_t)k * 2 * sizeof(*fB));
    if (!fB) return -3;
    uint16_t *sB = fB + k;
    perm_pairs(seedB, commitB, k, fB, sB);

    compute_bn_pack(B, EBR, bt_packed, fB, sB, k, n, nt);
    free(fB);
    return 0;
}

static int prep_a_side_impl(uint64_t seed, int8_t *A, const uint8_t *key, const uint8_t *commitB,
                int64_t m, int64_t k,
                int8_t *A_noised, int8_t *EAL, uint8_t *rootA, uint8_t *commitA,
                int nt, int cert_version) {
    if (nt < 1 || nt > prl_cpu_prep_threads()) nt = prl_cpu_prep_threads();
    if ((m * k) % 1024) return -1;
    if (k > (1 << 16)) return -2;

    stamp_seed(A, m * k, seed);
    calc_mk_seed_stamp(A, m * k, key, rootA);

    int cert_mode = cert_version >= 3 ? CERT_SALTED : CERT_LEGACY;
    uint8_t saltedA[32];
    if (cert_mode == CERT_SALTED) bind_root(rootA, (uint32_t)m, SEED_SALT_A, saltedA);
    else memcpy(saltedA, rootA, 32);

    blake3_hasher h;
    blake3_hasher_init(&h); blake3_hasher_update(&h, commitB, 32);
    blake3_hasher_update(&h, saltedA, 32); blake3_hasher_finalize(&h, commitA, 32);

    static const uint8_t seedA[32] = "A_tensor";

    return prepare_an_stamp(A, seedA, commitA, EAL, A_noised, m, k, nt);
}

/* Non-reuse APIs clear arbitrary storage; *_reuse APIs require dedicated,
 * initially calloc-zeroed buffers that are only modified by stamp_seed().
 * This avoids re-clearing 64 MiB each iteration without any runtime fill flag. */

int prep_a_side(uint64_t seed, int8_t *A, const uint8_t *key, const uint8_t *commitB,
                int64_t m, int64_t k,
                int8_t *A_noised, int8_t *EAL, uint8_t *rootA, uint8_t *commitA,
                int nt, int cert_version) {
    memset(A, 0, (size_t)(m * k));

    return prep_a_side_impl(seed, A, key, commitB, m, k, A_noised, EAL, rootA, commitA, nt, cert_version);
}

int prep_a_side_reuse(uint64_t seed, int8_t *A, const uint8_t *key, const uint8_t *commitB,
                int64_t m, int64_t k,
                int8_t *A_noised, int8_t *EAL, uint8_t *rootA, uint8_t *commitA,
                int nt, int cert_version) {
    return prep_a_side_impl(seed, A, key, commitB, m, k, A_noised, EAL, rootA, commitA, nt, cert_version);
}

int prep_b_side(uint64_t seed, int8_t *B, const uint8_t *key,
                int64_t n, int64_t k,
                int8_t *bt_packed, int8_t *EBR, uint8_t *rootB, uint8_t *commitB,
                int nt, int cert_version) {
    memset(B, 0, (size_t)(n * k));

    return prep_b_side_impl(seed, B, key, n, k, bt_packed, EBR, rootB, commitB, nt, cert_version);
}

int prep_b_side_reuse(uint64_t seed, int8_t *B, const uint8_t *key,
                int64_t n, int64_t k,
                int8_t *bt_packed, int8_t *EBR, uint8_t *rootB, uint8_t *commitB,
                int nt, int cert_version) {
    return prep_b_side_impl(seed, B, key, n, k, bt_packed, EBR, rootB, commitB, nt, cert_version);
}

int prep_random_reuse(uint64_t seed, int8_t *A, int8_t *B, const uint8_t *key,
                int64_t m, int64_t n, int64_t k,
                int8_t *A_noised, int8_t *Bt_noised, int8_t *EAL, int8_t *EBR,
                uint8_t *rootA, uint8_t *rootB, uint8_t *commitA, uint8_t *commitB,
                int nt, int cert_version) {
    return prep_random_impl(seed, A, B, key, m, n, k, A_noised, Bt_noised,
                            EAL, EBR, rootA, rootB, commitA, commitB, nt, 0,
                            cert_version >= 3 ? CERT_SALTED : CERT_LEGACY);
}

int prep_random_bt_reuse(uint64_t seed, int8_t *A, int8_t *B, const uint8_t *key,
                int64_t m, int64_t n, int64_t k,
                int8_t *A_noised, int8_t *bt_packed, int8_t *EAL, int8_t *EBR,
                uint8_t *rootA, uint8_t *rootB, uint8_t *commitA, uint8_t *commitB,
                int nt, int cert_version) {
    return prep_random_impl(seed, A, B, key, m, n, k, A_noised, bt_packed,
                            EAL, EBR, rootA, rootB, commitA, commitB, nt, 1,
                            cert_version >= 3 ? CERT_SALTED : CERT_LEGACY);
}
