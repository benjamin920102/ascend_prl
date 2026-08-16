#include <stdint.h>
#include <string.h>
#include <omp.h>
#include "blake3.h"

#if defined(__ARM_NEON) || defined(__aarch64__)
#include <arm_neon.h>
#define HAVE_NEON 1
#endif

#define DIGEST 32
#define ZERO_POINT 32
#define RANGE_MASK 63

/* ---- Salted-Seed fork (cert_version 3) ----------------------------------------------------
 * V3 changes only how the noise seeds are derived from the Merkle roots: each root is first
 * bound to its matrix dimension via a keyed BLAKE3 hash (domain-separated per side), before
 * feeding the (unchanged) b_noise_seed/a_noise_seed chain. Everything else -- circuits, wire
 * formats, share formats -- is unchanged. See docs/salted-seed-fork-upgrade-guide.md and
 * zk-pow/src/api/seed.rs (reference impl + pinned test vectors) in the pearl node repo.
 *
 * bound_a = blake3(hash_a || m_le32 || 28 zero bytes, key = blake3("pearl/cert-v3/noise-seed/A"))
 * bound_b = blake3(hash_b || n_le32 || 28 zero bytes, key = blake3("pearl/cert-v3/noise-seed/B"))
 *
 * The salts below are the hardcoded blake3("pearl/cert-v3/noise-seed/A"|"B") digests (consensus
 * must not depend on runtime string hashing), matching zk_pow::api::seed::SEED_SALT_A/SEED_SALT_B. */
static const uint8_t SEED_SALT_A[32] = {
    0x82, 0x49, 0x40, 0x6c, 0xa0, 0xed, 0x15, 0x16, 0x96, 0x16, 0xf6, 0x92, 0xfc, 0xf0, 0x76, 0xf8,
    0x92, 0xdb, 0xdb, 0x2a, 0x70, 0x23, 0xb8, 0x52, 0xf0, 0xd4, 0x77, 0x19, 0xc3, 0x90, 0x01, 0x7b,
};
static const uint8_t SEED_SALT_B[32] = {
    0x11, 0x30, 0x06, 0x32, 0xec, 0x63, 0x01, 0xca, 0x2b, 0xe2, 0xaf, 0x71, 0x8b, 0x3f, 0x4d, 0x4f,
    0x1a, 0xe9, 0xc6, 0x39, 0x88, 0xe8, 0xcc, 0x04, 0x48, 0x44, 0x30, 0x1d, 0x71, 0xb8, 0x9a, 0xa9,
};

/* root || dim(u32 LE) || 28 zero bytes -- exactly one 64-byte BLAKE3 block. */
static void bind_root(const uint8_t root[32], uint32_t dim, const uint8_t salt[32], uint8_t out[32]) {
    uint8_t msg[64] = {0};
    memcpy(msg, root, 32);
    memcpy(msg + 32, &dim, 4);   /* host is little-endian (aarch64); dim already in LE */
    blake3_hasher h;
    blake3_hasher_init_keyed(&h, salt);
    blake3_hasher_update(&h, msg, 64);
    blake3_hasher_finalize(&h, out, DIGEST);
}

/* CERT_LEGACY: pre-V3, roots feed the seed chain unsalted (cert_version 1 and 2).
 * CERT_SALTED: V3+, roots are bound to (m, n) first. */
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

static void fill_buf(int8_t *buf, int64_t total, uint64_t seed, int nt) {
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

static void unif_int8(const uint8_t *seed, const uint8_t *key, int64_t nbytes, int8_t *out, int nt) {
    int64_t draws = (nbytes + DIGEST - 1) / DIGEST;
    uint8_t *raw = (uint8_t *)out;

#pragma omp parallel for schedule(static) num_threads(nt)
    for (int64_t i = 0; i < draws; i++) {
        uint8_t d[DIGEST];
        draw_hash((uint32_t)i, seed, key, 0, d);
        int64_t off = i * DIGEST, n = nbytes - off;
        if (n > DIGEST) n = DIGEST;
        memcpy(raw + off, d, (size_t)n);
    }

#ifdef HAVE_NEON
    int64_t nvec = nbytes / 16; /* number of full 16-byte NEON chunks */
#pragma omp parallel for schedule(static) num_threads(nt)
    for (int64_t v = 0; v < nvec; v++) {
        int64_t i = v * 16;
        /* NEON vandq_u8/vsubq_s8 are lane-wise mod-256 ops, bit-identical
           to the scalar (raw[i] & MASK) - ZP for every byte. */
        uint8x16_t x = vld1q_u8(raw + i);
        x = vandq_u8(x, vdupq_n_u8(RANGE_MASK));
        int8x16_t sv = vsubq_s8(vreinterpretq_s8_u8(x), vdupq_n_s8(ZERO_POINT));
        vst1q_s8(out + i, sv);
    }
    for (int64_t i = nvec * 16; i < nbytes; i++) {
        out[i] = (int8_t)((raw[i] & RANGE_MASK) - ZERO_POINT);
    }
#else
#pragma omp parallel for schedule(static) num_threads(nt)
    for (int64_t i = 0; i < nbytes; i++) {
        out[i] = (int8_t)((raw[i] & RANGE_MASK) - ZERO_POINT);
    }
#endif
}

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

static void compute_an(const int8_t *A, const int8_t *EAL, int8_t *out,
                       const uint16_t *f, const uint16_t *s,
                       int64_t m, int64_t k, int R, int nt) {
#pragma omp parallel for schedule(static) num_threads(nt)
    for (int64_t r = 0; r < m; r++) {
        const int8_t *ar = A + r * k, *el = EAL + r * R;
        int8_t *o = out + r * k;
        int64_t j = 0;
#ifdef HAVE_NEON
        int8_t efb[16], esb[16];
        for (; j + 16 <= k; j += 16) {
            /* EAL[f[.]]/EAL[s[.]] are data-dependent gathers; ARM NEON has
               no int8 gather, so collect scalarly into small buffers, then
               do the add/sub with vector ops. vaddq_s8/vsubq_s8 are
               lane-wise mod-256, matching scalar int8_t wraparound exactly,
               and we preserve the original (a + f) - s evaluation order. */
            for (int t = 0; t < 16; t++) {
                efb[t] = el[f[j + t]];
                esb[t] = el[s[j + t]];
            }
            int8x16_t va = vld1q_s8(ar + j);
            int8x16_t vf = vld1q_s8(efb);
            int8x16_t vs = vld1q_s8(esb);
            int8x16_t vo = vsubq_s8(vaddq_s8(va, vf), vs);
            vst1q_s8(o + j, vo);
        }
#endif
        for (; j < k; j++)
            o[j] = (int8_t)(ar[j] + el[f[j]] - el[s[j]]);
    }
}

#define TB 64
static void compute_bn(const int8_t *B, const int8_t *EBR, int8_t *out,
                       const uint16_t *f, const uint16_t *s,
                       int64_t k, int64_t n, int R, int nt) {
    int64_t kb = (k + TB - 1) / TB;
#pragma omp parallel for schedule(static) num_threads(nt)
    for (int64_t ib = 0; ib < kb; ib++) {
        int64_t i0 = ib * TB, i1 = i0 + TB > k ? k : i0 + TB;
        for (int64_t j0 = 0; j0 < n; j0 += TB) {
            int64_t j1 = j0 + TB > n ? n : j0 + TB;
            for (int64_t j = j0; j < j1; j++) {
                const int8_t *bj = B + j * k, *ej = EBR + j * R;
                for (int64_t i = i0; i < i1; i++)
                    out[i * n + j] = (int8_t)(bj[i] + ej[f[i]] - ej[s[i]]);
            }
        }
    }
}

#define BN_PACK 64
static void compute_bn_pack(const int8_t *B, const int8_t *EBR, int8_t *bt,
                            const uint16_t *f, const uint16_t *s,
                            int64_t k, int64_t n, int R, int nt) {
    int64_t nbands = n / BN_PACK, NFOLD = k / R;
#pragma omp parallel for schedule(static) num_threads(nt)
    for (int64_t jp = 0; jp < nbands; jp++) {
        for (int64_t p = 0; p < NFOLD; p++) {
            for (int64_t m = 0; m < BN_PACK; m++) {
                int64_t col = jp * BN_PACK + m;
                const int8_t *bcol = B + col * k;
                const int8_t *ecol = EBR + col * R;
                int8_t *dst = bt + ((jp * NFOLD + p) * BN_PACK + m) * R;
                for (int64_t ki = 0; ki < R; ki++) {
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
                 int nt, int pack, int cert_mode) {
    if ((m * k) % 1024 || (n * k) % 1024) return -1;

#pragma omp parallel sections num_threads(2)
    {
#pragma omp section
        calc_mk(A, m * k, key, rootA);
#pragma omp section
        calc_mk(B, n * k, key, rootB);
    }

    uint8_t saltedA[32], saltedB[32];
    salt_roots(cert_mode, rootA, rootB, (uint32_t)m, (uint32_t)n, saltedA, saltedB);

    blake3_hasher h;
    blake3_hasher_init(&h); blake3_hasher_update(&h, key, 32);
    blake3_hasher_update(&h, saltedB, 32); blake3_hasher_finalize(&h, commitB, 32);
    blake3_hasher_init(&h); blake3_hasher_update(&h, commitB, 32);
    blake3_hasher_update(&h, saltedA, 32); blake3_hasher_finalize(&h, commitA, 32);

    static const uint8_t seedA[32] = "A_tensor", seedB[32] = "B_tensor";
    unif_int8(seedA, commitA, m * R, EAL, nt);
    unif_int8(seedB, commitB, n * R, EBR, nt);

    static uint16_t fA[1 << 16], sA[1 << 16], fB[1 << 16], sB[1 << 16];
    if (k > (1 << 16)) return -2;
    perm_pairs(seedA, commitA, k, R, fA, sA);
    perm_pairs(seedB, commitB, k, R, fB, sB);

    compute_an(A, EAL, A_noised, fA, sA, m, k, R, nt);
    if (pack) {
        compute_bn_pack(B, EBR, Bt_out, fB, sB, k, n, R, nt);
    } else {
        compute_bn(B, EBR, Bt_out, fB, sB, k, n, R, nt);
    }
    return 0;
}

int prep_from_ab(const int8_t *A, const int8_t *B, const uint8_t *key,
                 int64_t m, int64_t n, int64_t k, int R,
                 int8_t *A_noised, int8_t *Bt_noised, int8_t *EAL, int8_t *EBR,
                 uint8_t *rootA, uint8_t *rootB, uint8_t *commitA, uint8_t *commitB,
                 int nt, int cert_version) {
    int cert_mode = cert_version >= 3 ? CERT_SALTED : CERT_LEGACY;
    return prep_from_ab_impl(A, B, key, m, n, k, R, A_noised, Bt_noised,
                             EAL, EBR, rootA, rootB, commitA, commitB, nt, 0, cert_mode);
}

static int prep_random_impl(uint64_t seed, int8_t *A, int8_t *B, const uint8_t *key,
                int64_t m, int64_t n, int64_t k, int R,
                int8_t *A_noised, int8_t *Bt_out, int8_t *EAL, int8_t *EBR,
                uint8_t *rootA, uint8_t *rootB, uint8_t *commitA, uint8_t *commitB,
                int nt, int pack, int cert_mode) {
    fill_buf(A, m * k, seed, nt);
    fill_buf(B, n * k, seed ^ 0xB0B0B0B0ULL, nt);
    return prep_from_ab_impl(A, B, key, m, n, k, R, A_noised, Bt_out,
                             EAL, EBR, rootA, rootB, commitA, commitB, nt, pack, cert_mode);
}

int prep_random(uint64_t seed, int8_t *A, int8_t *B, const uint8_t *key,
                int64_t m, int64_t n, int64_t k, int R,
                int8_t *A_noised, int8_t *Bt_noised, int8_t *EAL, int8_t *EBR,
                uint8_t *rootA, uint8_t *rootB, uint8_t *commitA, uint8_t *commitB,
                int nt, int cert_version) {
    int cert_mode = cert_version >= 3 ? CERT_SALTED : CERT_LEGACY;
    return prep_random_impl(seed, A, B, key, m, n, k, R, A_noised, Bt_noised,
                            EAL, EBR, rootA, rootB, commitA, commitB, nt, 0, cert_mode);
}

int prep_random_bt(uint64_t seed, int8_t *A, int8_t *B, const uint8_t *key,
                int64_t m, int64_t n, int64_t k, int R,
                int8_t *A_noised, int8_t *bt_packed, int8_t *EAL, int8_t *EBR,
                uint8_t *rootA, uint8_t *rootB, uint8_t *commitA, uint8_t *commitB,
                int nt, int cert_version) {
    int cert_mode = cert_version >= 3 ? CERT_SALTED : CERT_LEGACY;
    return prep_random_impl(seed, A, B, key, m, n, k, R, A_noised, bt_packed,
                            EAL, EBR, rootA, rootB, commitA, commitB, nt, 1, cert_mode);
}

int prep_b_side(uint64_t seed, int8_t *B, const uint8_t *key,
                int64_t n, int64_t k, int R,
                int8_t *bt_packed, int8_t *EBR, uint8_t *rootB, uint8_t *commitB,
                int nt, int cert_version) {
    if ((n * k) % 1024) return -1;
    if (k > (1 << 16)) return -2;

    fill_buf(B, n * k, seed, nt);
    calc_mk(B, n * k, key, rootB);

    int cert_mode = cert_version >= 3 ? CERT_SALTED : CERT_LEGACY;
    uint8_t saltedB[32];
    if (cert_mode == CERT_SALTED) bind_root(rootB, (uint32_t)n, SEED_SALT_B, saltedB);
    else memcpy(saltedB, rootB, 32);

    blake3_hasher h;
    blake3_hasher_init(&h); blake3_hasher_update(&h, key, 32);
    blake3_hasher_update(&h, saltedB, 32); blake3_hasher_finalize(&h, commitB, 32);

    static const uint8_t seedB[32] = "B_tensor";
    unif_int8(seedB, commitB, n * R, EBR, nt);

    static uint16_t fB[1 << 16], sB[1 << 16];
    perm_pairs(seedB, commitB, k, R, fB, sB);

    compute_bn_pack(B, EBR, bt_packed, fB, sB, k, n, R, nt);
    return 0;
}

int prep_a_side(uint64_t seed, int8_t *A, const uint8_t *key, const uint8_t *commitB,
                int64_t m, int64_t k, int R,
                int8_t *A_noised, int8_t *EAL, uint8_t *rootA, uint8_t *commitA,
                int nt, int cert_version) {
    if ((m * k) % 1024) return -1;
    if (k > (1 << 16)) return -2;

    fill_buf(A, m * k, seed, nt);
    calc_mk(A, m * k, key, rootA);

    int cert_mode = cert_version >= 3 ? CERT_SALTED : CERT_LEGACY;
    uint8_t saltedA[32];
    if (cert_mode == CERT_SALTED) bind_root(rootA, (uint32_t)m, SEED_SALT_A, saltedA);
    else memcpy(saltedA, rootA, 32);

    blake3_hasher h;
    blake3_hasher_init(&h); blake3_hasher_update(&h, commitB, 32);
    blake3_hasher_update(&h, saltedA, 32); blake3_hasher_finalize(&h, commitA, 32);

    static const uint8_t seedA[32] = "A_tensor";
    unif_int8(seedA, commitA, m * R, EAL, nt);

    static uint16_t fA[1 << 16], sA[1 << 16];
    perm_pairs(seedA, commitA, k, R, fA, sA);

    compute_an(A, EAL, A_noised, fA, sA, m, k, R, nt);
    return 0;
}
