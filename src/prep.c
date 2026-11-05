#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <omp.h>
#include "blake3.h"
#include "blake3_impl.h" /* upstream BLAKE3 compression primitives and flag definitions */
#include "cpu_budget.h"

#if defined(__ARM_NEON) || defined(__aarch64__)
#include <arm_neon.h>
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

// Hash a fixed 64-byte block: root || dimension (LE u32) || 28 zero bytes.
static void bind_root(const uint8_t root[32], uint32_t dim, const uint8_t salt[32], uint8_t out[32]) {
    uint8_t msg[64] = {0};
    memcpy(msg, root, 32);
    memcpy(msg + 32, &dim, 4);
    blake3_hasher h;
    blake3_hasher_init_keyed(&h, salt);
    blake3_hasher_update(&h, msg, 64);
    blake3_hasher_finalize(&h, out, DIGEST);
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

typedef struct { uint64_t s[4]; } rng_t;

static uint64_t splitmix(uint64_t *x) {
    uint64_t z = (*x += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

static void rng_seed(rng_t *r, uint64_t seed) {
    for (int i = 0; i < 4; i++) r->s[i] = splitmix(&seed);
}

static inline uint64_t rotl64(uint64_t x, int k) {
    return (x << k) | (x >> (64 - k));
}

static inline uint64_t rng_next(rng_t *r) {
    uint64_t *s = r->s, res = rotl64(s[1] * 5, 7) * 9, t = s[1] << 17;
    s[2] ^= s[0]; s[3] ^= s[1]; s[1] ^= s[2]; s[0] ^= s[3]; s[2] ^= t; s[3] = rotl64(s[3], 45);
    return res;
}

static void draw_hash(uint32_t idx, const uint8_t *seed, const uint8_t *key,
                      int slot, uint8_t out[DIGEST]) {
    uint8_t msg[64] = {0};
    uint32_t v = idx + 1;
    memcpy(msg + slot * 4, &v, 4);
    memcpy(msg + 32, seed, 32);
    blake3_hasher h;
    blake3_hasher_init_keyed(&h, key);
    blake3_hasher_update(&h, msg, 64);
    blake3_hasher_finalize(&h, out, DIGEST);
}

/*
 * Default: zero-fill + 8-byte seed stamp (gzip-friendly; ~10-100x compression on proofs).
 * PRL_ZERO_SEED=0: legacy uniform random fill (incompressible).
 */
static int zero_seed_enabled(void) {
    const char *zs = getenv("PRL_ZERO_SEED");
    return !(zs && zs[0] == '0' && zs[1] == '\0');
}

/* zero_initialized is an explicit caller contract: this allocation was initially
 * zeroed and has only been written by fill_buf since then. Never infer this
 * property from a recycled address. Legacy/external buffers still get memset. */
static int fill_buf(int8_t *buf, int64_t total, uint64_t seed, int nt, int zero_initialized) {
    if (!zero_seed_enabled()) {
#pragma omp parallel num_threads(nt)
        {
            int t = omp_get_thread_num();
            int num_t = omp_get_num_threads();
            int64_t lo = total * t / num_t, hi = total * (t + 1) / num_t;
            rng_t r;
            rng_seed(&r, seed + 0x9E37 * (uint64_t)(t + 1));
            int64_t i = lo;
            while (i < hi) {
                uint64_t v = rng_next(&r);
                for (int b = 0; b < 8 && i < hi; b++, v >>= 8)
                    buf[i++] = (int8_t)((uint8_t)v % 127) - 63;
            }
        }
        return 0;
    }
    if (!zero_initialized) memset(buf, 0, (size_t)total);
    if (total >= 8) {
        uint64_t s = seed;
        for (int i = 0; i < 8; i++, s >>= 8)
            buf[i] = (int8_t)(s & 0xff);
    }
    (void)nt;
    /* The caller may use the zero-seed fast path only under this explicit
     * fill contract; no whole-matrix scan is needed to rediscover it. */
    return 1;
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
 * The caller must supply the explicit fill_buf() zero-seed contract; this
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

static void calc_mk_filled(const int8_t *buf, int64_t len, const uint8_t *key,
                           uint8_t *root, int known_zero_seed) {
    if (known_zero_seed && calc_mk_zero_seed_cached(buf, len, key, root)) return;
    calc_mk(buf, len, key, root);
}

static void unif_int8(const uint8_t *seed, const uint8_t *key, int64_t nbytes, int8_t *out, int nt) {
    int64_t draws = (nbytes + DIGEST - 1) / DIGEST;

#pragma omp parallel for schedule(static) num_threads(nt)
    for (int64_t i = 0; i < draws; i++) {
        uint8_t d[DIGEST];
        draw_hash((uint32_t)i, seed, key, 0, d);
        int64_t off = i * DIGEST, n = nbytes - off;
        if (n > DIGEST) n = DIGEST;
        // Transform each digest before writing it, avoiding a second pass over EAL/EBR.
#ifdef HAVE_NEON
        if (n == DIGEST) {
            uint8x16_t mask = vdupq_n_u8(RANGE_MASK);
            int8x16_t zero = vdupq_n_s8(ZERO_POINT);
            uint8x16_t lo = vandq_u8(vld1q_u8(d), mask);
            uint8x16_t hi = vandq_u8(vld1q_u8(d + 16), mask);
            vst1q_s8(out + off, vsubq_s8(vreinterpretq_s8_u8(lo), zero));
            vst1q_s8(out + off + 16, vsubq_s8(vreinterpretq_s8_u8(hi), zero));
            continue;
        }
#endif
        for (int64_t j = 0; j < n; j++) {
            out[off + j] = (int8_t)((d[j] & RANGE_MASK) - ZERO_POINT);
        }
    }
}

// Each index pair is deterministically derived from the commitment; XOR ensures
// the second rank index differs from the first without a rejection loop.
static void perm_pairs(const uint8_t *seed, const uint8_t *key, int64_t lines, int rank,
                       uint16_t *first, uint16_t *second) {
    int64_t draws = (lines * 4 + DIGEST - 1) / DIGEST;
    for (int64_t i = 0; i < draws; i++) {
        uint8_t d[DIGEST];
        draw_hash((uint32_t)i, seed, key, 1, d);
        for (int j = 0; j < 8; j++) {
            int64_t line = i * 8 + j;
            if (line >= lines) break;
            uint32_t u;
            memcpy(&u, d + j * 4, 4);
            uint32_t f = u & (uint32_t)(rank - 1);
            uint32_t s = f ^ (1u + (uint32_t)(((uint64_t)(rank - 1) * u) >> 32));
            first[line] = (uint16_t)f;
            second[line] = (uint16_t)s;
        }
    }
}

/* AArch64 TBL gathers 16 noise values directly from register tables.
 * Keep the uint16_t permutation representation for ranks > 256 and use the
 * low byte only in this rank-128 specialization (all indices are < 128).
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
#endif

static void compute_an(const int8_t *A, const int8_t *EAL, int8_t *out,
                       const uint16_t *f, const uint16_t *s,
                       int64_t m, int64_t k, int R, int nt, int zero_seed) {
#pragma omp parallel for schedule(static) num_threads(nt)
    for (int64_t r = 0; r < m; r++) {
        const int8_t *ar = zero_seed ? NULL : A + r * k;
        const int8_t *el = EAL + r * R;
        int8_t *o = out + r * k;
#if defined(__aarch64__)
        if (R == 128) {
            noise128_apply(noise128_load(el), ar, o, f, s, k);
            continue;
        }
#endif
        int64_t j = 0;
#ifdef HAVE_NEON
        int8_t efb[16], esb[16];
        for (; j + 16 <= k; j += 16) {
            for (int t = 0; t < 16; t++) {
                efb[t] = el[f[j + t]];
                esb[t] = el[s[j + t]];
            }
            int8x16_t va = ar ? vld1q_s8(ar + j) : vdupq_n_s8(0);
            vst1q_s8(o + j, vsubq_s8(vaddq_s8(va, vld1q_s8(efb)), vld1q_s8(esb)));
        }
#endif
        for (; j < k; j++)
            o[j] = (int8_t)((ar ? ar[j] : 0) + el[f[j]] - el[s[j]]);
    }
    /* Original matrix bytes 0..7 are the seed stamp, all other bytes are zero.
     * Add with int8 wrap, exactly as in the ordinary A+noise path. */
    if (zero_seed && m * k >= 8)
        for (int i = 0; i < 8; ++i) out[i] = (int8_t)(out[i] + A[i]);
}

#define TB 64
static void compute_bn(const int8_t *B, const int8_t *EBR, int8_t *out,
                       const uint16_t *f, const uint16_t *s,
                       int64_t k, int64_t n, int R, int nt) {
    int64_t kb = (k + TB - 1) / TB;
#pragma omp parallel for schedule(static) num_threads(nt)
    for (int64_t ib = 0; ib < kb; ib++) {
        int64_t i0 = ib * TB, ni = k - i0 < TB ? k - i0 : TB;
        int8_t tile[TB][TB];
        for (int64_t j0 = 0; j0 < n; j0 += TB) {
            int64_t nj = n - j0 < TB ? n - j0 : TB;
            for (int64_t j = 0; j < nj; ++j) {
                const int8_t *bj = B + (j0 + j) * k + i0;
                const int8_t *ej = EBR + (j0 + j) * R;
#if defined(__aarch64__)
                if (R == 128) {
                    noise128_apply(noise128_load(ej), bj, tile[j], f + i0, s + i0, ni);
                    continue;
                }
#endif
                for (int64_t i = 0; i < ni; ++i)
                    tile[j][i] = (int8_t)(bj[i] + ej[f[i0 + i]] - ej[s[i0 + i]]);
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
                            int64_t k, int64_t n, int R, int nt) {
    int64_t nbands = n / BN_PACK, NFOLD = k / R;
#pragma omp parallel for schedule(static) num_threads(nt)
    for (int64_t jp = 0; jp < nbands; jp++) {
        /* One column at a time reuses its noise row across all folds and
         * reads its source B column sequentially. The packed offset is unchanged. */
        for (int64_t col_in_band = 0; col_in_band < BN_PACK; col_in_band++) {
            int64_t col = jp * BN_PACK + col_in_band;
            const int8_t *bcol = B + col * k;
            const int8_t *ecol = EBR + col * R;
#if defined(__aarch64__)
            if (R == 128) {
                noise128_t t = noise128_load(ecol);
                for (int64_t p = 0; p < NFOLD; ++p) {
                    int64_t row = p * R;
                    int8_t *dst = bt + ((jp * NFOLD + p) * BN_PACK + col_in_band) * R;
                    noise128_apply(t, bcol + row, dst, f + row, s + row, R);
                }
                continue;
            }
#endif
            for (int64_t p = 0; p < NFOLD; ++p) {
                int8_t *dst = bt + ((jp * NFOLD + p) * BN_PACK + col_in_band) * R;
                for (int64_t ki = 0; ki < R; ++ki) {
                    int64_t row = p * R + ki;
                    dst[ki] = (int8_t)(bcol[row] + ecol[f[row]] - ecol[s[row]]);
                }
            }
        }
    }
}

static int prep_from_ab_impl(const int8_t *A, const int8_t *B, const uint8_t *key,
                 int64_t m, int64_t n, int64_t k, int R,
                 int8_t *A_noised, int8_t *Bt_out,
                 int8_t *EAL, int8_t *EBR,
                 uint8_t *rootA, uint8_t *rootB,
                 uint8_t *commitA, uint8_t *commitB,
                 int nt, int pack, int cert_mode, int zero_a, int zero_b) {
    if (nt < 1 || nt > prl_cpu_prep_threads()) nt = prl_cpu_prep_threads();
    if ((m * k) % 1024 || (n * k) % 1024) return -1;

    /* The persistent hash team already fills the prep partition. Avoid two
     * independent root callers competing for that same helper budget. */
    calc_mk_filled(A, m * k, key, rootA, zero_a);
    calc_mk_filled(B, n * k, key, rootB, zero_b);

    uint8_t saltedA[32], saltedB[32];
    salt_roots(cert_mode, rootA, rootB, (uint32_t)m, (uint32_t)n, saltedA, saltedB);

    // B commits first; A commits to B, so the two noise seeds are linked.
    blake3_hasher h;
    blake3_hasher_init(&h); blake3_hasher_update(&h, key, 32);
    blake3_hasher_update(&h, saltedB, 32); blake3_hasher_finalize(&h, commitB, 32);
    blake3_hasher_init(&h); blake3_hasher_update(&h, commitB, 32);
    blake3_hasher_update(&h, saltedA, 32); blake3_hasher_finalize(&h, commitA, 32);

    static const uint8_t seedA[32] = "A_tensor", seedB[32] = "B_tensor";
    unif_int8(seedA, commitA, m * R, EAL, nt);
    unif_int8(seedB, commitB, n * R, EBR, nt);

    if (k > (1 << 16)) return -2;
    uint16_t *pairs = malloc((size_t)k * 4 * sizeof(*pairs));
    if (!pairs) return -3;
    uint16_t *fA = pairs, *sA = fA + k, *fB = sA + k, *sB = fB + k;
    perm_pairs(seedA, commitA, k, R, fA, sA);
    perm_pairs(seedB, commitB, k, R, fB, sB);

    compute_an(A, EAL, A_noised, fA, sA, m, k, R, nt, zero_a);
    if (pack) {
        compute_bn_pack(B, EBR, Bt_out, fB, sB, k, n, R, nt);
    } else {
        compute_bn(B, EBR, Bt_out, fB, sB, k, n, R, nt);
    }
    free(pairs);
    return 0;
}

int prep_from_ab(const int8_t *A, const int8_t *B, const uint8_t *key,
                 int64_t m, int64_t n, int64_t k, int R,
                 int8_t *A_noised, int8_t *Bt_noised, int8_t *EAL, int8_t *EBR,
                 uint8_t *rootA, uint8_t *rootB, uint8_t *commitA, uint8_t *commitB,
                 int nt, int cert_version) {
    int cert_mode = cert_version >= 3 ? CERT_SALTED : CERT_LEGACY;
    return prep_from_ab_impl(A, B, key, m, n, k, R, A_noised, Bt_noised,
                             EAL, EBR, rootA, rootB, commitA, commitB, nt, 0, cert_mode, 0, 0);
}

static int prep_random_impl(uint64_t seed, int8_t *A, int8_t *B, const uint8_t *key,
                            int64_t m, int64_t n, int64_t k, int R,
                            int8_t *A_noised, int8_t *Bt_out, int8_t *EAL, int8_t *EBR,
                            uint8_t *rootA, uint8_t *rootB, uint8_t *commitA, uint8_t *commitB,
                            int nt, int pack, int cert_mode, int zero_initialized) {
    if (nt < 1 || nt > prl_cpu_prep_threads()) nt = prl_cpu_prep_threads();
    int zero_a = fill_buf(A, m * k, seed, nt, zero_initialized);
    int zero_b = fill_buf(B, n * k, seed ^ 0xB0B0B0B0ULL, nt, zero_initialized);
    return prep_from_ab_impl(A, B, key, m, n, k, R, A_noised, Bt_out,
                             EAL, EBR, rootA, rootB, commitA, commitB, nt, pack,
                             cert_mode, zero_a, zero_b);
}

int prep_random(uint64_t seed, int8_t *A, int8_t *B, const uint8_t *key,
                int64_t m, int64_t n, int64_t k, int R,
                int8_t *A_noised, int8_t *Bt_noised, int8_t *EAL, int8_t *EBR,
                uint8_t *rootA, uint8_t *rootB, uint8_t *commitA, uint8_t *commitB,
                int nt, int cert_version) {
    int cert_mode = cert_version >= 3 ? CERT_SALTED : CERT_LEGACY;
    return prep_random_impl(seed, A, B, key, m, n, k, R, A_noised, Bt_noised,
                            EAL, EBR, rootA, rootB, commitA, commitB, nt, 0, cert_mode, 0);
}

int prep_random_bt(uint64_t seed, int8_t *A, int8_t *B, const uint8_t *key,
                int64_t m, int64_t n, int64_t k, int R,
                int8_t *A_noised, int8_t *bt_packed, int8_t *EAL, int8_t *EBR,
                uint8_t *rootA, uint8_t *rootB, uint8_t *commitA, uint8_t *commitB,
                int nt, int cert_version) {
    int cert_mode = cert_version >= 3 ? CERT_SALTED : CERT_LEGACY;
    return prep_random_impl(seed, A, B, key, m, n, k, R, A_noised, bt_packed,
                            EAL, EBR, rootA, rootB, commitA, commitB, nt, 1, cert_mode, 0);
}

static int prep_b_side_impl(uint64_t seed, int8_t *B, const uint8_t *key,
                int64_t n, int64_t k, int R,
                int8_t *bt_packed, int8_t *EBR, uint8_t *rootB, uint8_t *commitB,
                int nt, int cert_version, int zero_initialized) {
    if (nt < 1 || nt > prl_cpu_prep_threads()) nt = prl_cpu_prep_threads();
    if ((n * k) % 1024) return -1;
    if (k > (1 << 16)) return -2;

    int zero_seed = fill_buf(B, n * k, seed, nt, zero_initialized);
    calc_mk_filled(B, n * k, key, rootB, zero_seed);

    int cert_mode = cert_version >= 3 ? CERT_SALTED : CERT_LEGACY;
    uint8_t saltedB[32];
    if (cert_mode == CERT_SALTED) bind_root(rootB, (uint32_t)n, SEED_SALT_B, saltedB);
    else memcpy(saltedB, rootB, 32);

    blake3_hasher h;
    blake3_hasher_init(&h); blake3_hasher_update(&h, key, 32);
    blake3_hasher_update(&h, saltedB, 32); blake3_hasher_finalize(&h, commitB, 32);

    static const uint8_t seedB[32] = "B_tensor";
    unif_int8(seedB, commitB, n * R, EBR, nt);

    uint16_t *fB = malloc((size_t)k * 2 * sizeof(*fB));
    if (!fB) return -3;
    uint16_t *sB = fB + k;
    perm_pairs(seedB, commitB, k, R, fB, sB);

    compute_bn_pack(B, EBR, bt_packed, fB, sB, k, n, R, nt);
    free(fB);
    return 0;
}

static int prep_a_side_impl(uint64_t seed, int8_t *A, const uint8_t *key, const uint8_t *commitB,
                int64_t m, int64_t k, int R,
                int8_t *A_noised, int8_t *EAL, uint8_t *rootA, uint8_t *commitA,
                int nt, int cert_version, int zero_initialized) {
    if (nt < 1 || nt > prl_cpu_prep_threads()) nt = prl_cpu_prep_threads();
    if ((m * k) % 1024) return -1;
    if (k > (1 << 16)) return -2;

    int zero_seed = fill_buf(A, m * k, seed, nt, zero_initialized);
    calc_mk_filled(A, m * k, key, rootA, zero_seed);

    int cert_mode = cert_version >= 3 ? CERT_SALTED : CERT_LEGACY;
    uint8_t saltedA[32];
    if (cert_mode == CERT_SALTED) bind_root(rootA, (uint32_t)m, SEED_SALT_A, saltedA);
    else memcpy(saltedA, rootA, 32);

    blake3_hasher h;
    blake3_hasher_init(&h); blake3_hasher_update(&h, commitB, 32);
    blake3_hasher_update(&h, saltedA, 32); blake3_hasher_finalize(&h, commitA, 32);

    static const uint8_t seedA[32] = "A_tensor";
    unif_int8(seedA, commitA, m * R, EAL, nt);

    uint16_t *fA = malloc((size_t)k * 2 * sizeof(*fA));
    if (!fA) return -3;
    uint16_t *sA = fA + k;
    perm_pairs(seedA, commitA, k, R, fA, sA);

    compute_an(A, EAL, A_noised, fA, sA, m, k, R, nt, zero_seed);
    free(fA);
    return 0;
}

/* Existing APIs clear arbitrary input storage; the *_reuse variants require
 * calloc-owned buffers exclusively maintained by these generators. The fill
 * mode must remain fixed for that allocation's lifetime. */

int prep_a_side(uint64_t seed, int8_t *A, const uint8_t *key, const uint8_t *commitB,
                int64_t m, int64_t k, int R,
                int8_t *A_noised, int8_t *EAL, uint8_t *rootA, uint8_t *commitA,
                int nt, int cert_version) {
    return prep_a_side_impl(seed, A, key, commitB, m, k, R, A_noised, EAL, rootA, commitA, nt, cert_version, 0);
}

int prep_a_side_reuse(uint64_t seed, int8_t *A, const uint8_t *key, const uint8_t *commitB,
                int64_t m, int64_t k, int R,
                int8_t *A_noised, int8_t *EAL, uint8_t *rootA, uint8_t *commitA,
                int nt, int cert_version) {
    return prep_a_side_impl(seed, A, key, commitB, m, k, R, A_noised, EAL, rootA, commitA, nt, cert_version, 1);
}

int prep_b_side(uint64_t seed, int8_t *B, const uint8_t *key,
                int64_t n, int64_t k, int R,
                int8_t *bt_packed, int8_t *EBR, uint8_t *rootB, uint8_t *commitB,
                int nt, int cert_version) {
    return prep_b_side_impl(seed, B, key, n, k, R, bt_packed, EBR, rootB, commitB, nt, cert_version, 0);
}

int prep_b_side_reuse(uint64_t seed, int8_t *B, const uint8_t *key,
                int64_t n, int64_t k, int R,
                int8_t *bt_packed, int8_t *EBR, uint8_t *rootB, uint8_t *commitB,
                int nt, int cert_version) {
    return prep_b_side_impl(seed, B, key, n, k, R, bt_packed, EBR, rootB, commitB, nt, cert_version, 1);
}

int prep_random_reuse(uint64_t seed, int8_t *A, int8_t *B, const uint8_t *key,
                int64_t m, int64_t n, int64_t k, int R,
                int8_t *A_noised, int8_t *Bt_noised, int8_t *EAL, int8_t *EBR,
                uint8_t *rootA, uint8_t *rootB, uint8_t *commitA, uint8_t *commitB,
                int nt, int cert_version) {
    return prep_random_impl(seed, A, B, key, m, n, k, R, A_noised, Bt_noised,
                            EAL, EBR, rootA, rootB, commitA, commitB, nt, 0,
                            cert_version >= 3 ? CERT_SALTED : CERT_LEGACY, 1);
}

int prep_random_bt_reuse(uint64_t seed, int8_t *A, int8_t *B, const uint8_t *key,
                int64_t m, int64_t n, int64_t k, int R,
                int8_t *A_noised, int8_t *bt_packed, int8_t *EAL, int8_t *EBR,
                uint8_t *rootA, uint8_t *rootB, uint8_t *commitA, uint8_t *commitB,
                int nt, int cert_version) {
    return prep_random_impl(seed, A, B, key, m, n, k, R, A_noised, bt_packed,
                            EAL, EBR, rootA, rootB, commitA, commitB, nt, 1,
                            cert_version >= 3 ? CERT_SALTED : CERT_LEGACY, 1);
}
