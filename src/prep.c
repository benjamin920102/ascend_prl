#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include "blake3.h"

#define DIGEST 32
#define ZERO_POINT 32
#define RANGE_MASK 63
#define MAX_THREADS 256

typedef struct { int t, nt; void *ctx; void *(*fn)(void *); } span_t;

typedef struct worker_slot {
    struct threadpool *pool;
    int id;
    void *(*fn)(void *);
    span_t sp;
    int have_job;
    int done;
} worker_slot_t;

static pthread_mutex_t g_pool_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_pool_cv_go = PTHREAD_COND_INITIALIZER;
static pthread_cond_t g_pool_cv_done = PTHREAD_COND_INITIALIZER;

typedef struct threadpool {
    int nt;
    pthread_t th[MAX_THREADS];
    worker_slot_t slot[MAX_THREADS];
    int generation;
    int completed;
    int shutdown;
} threadpool_t;

static threadpool_t g_pool;
static int g_pool_inited = 0;
static pthread_mutex_t g_init_mu = PTHREAD_MUTEX_INITIALIZER;

static void *tp_thread_main(void *arg) {
    worker_slot_t *s = arg;
    for (;;) {
        pthread_mutex_lock(&g_pool_mu);
        while (!s->have_job && !g_pool.shutdown)
            pthread_cond_wait(&g_pool_cv_go, &g_pool_mu);
        int shutdown = g_pool.shutdown;
        int have_job = s->have_job;
        void *(*fn)(void *) = s->fn;
        span_t sp = s->sp;
        pthread_mutex_unlock(&g_pool_mu);

        if (!have_job) { if (shutdown) return 0; continue; }

        fn(&sp);

        pthread_mutex_lock(&g_pool_mu);
        s->have_job = 0;
        s->done = 1;
        g_pool.completed++;
        pthread_cond_signal(&g_pool_cv_done);
        pthread_mutex_unlock(&g_pool_mu);
    }
    return 0;
}

static void pool_init(int nt) {
    pthread_mutex_lock(&g_init_mu);
    if (!g_pool_inited) {
        if (nt > MAX_THREADS) nt = MAX_THREADS;
        if (nt < 1) nt = 1;
        g_pool.nt = nt;
        g_pool.generation = 0;
        g_pool.completed = 0;
        g_pool.shutdown = 0;
        for (int i = 0; i < nt; i++) {
            g_pool.slot[i].pool = &g_pool;
            g_pool.slot[i].id = i;
            g_pool.slot[i].have_job = 0;
            g_pool.slot[i].done = 0;
            pthread_create(&g_pool.th[i], 0, tp_thread_main, &g_pool.slot[i]);
        }
        g_pool_inited = 1;
    }
    pthread_mutex_unlock(&g_init_mu);
}

/* run fn across nt spans using the persistent pool if nt matches pool size and
 * pool is initialized; otherwise fall back to ad-hoc pthread_create (still
 * bit-exact, just no pooling benefit). This keeps behavior identical for any
 * caller that varies nt across calls. */
static void run_threads(int nt, void *(*fn)(void *), void *ctx) {
    if (nt <= 1) {
        span_t single_span = { 0, 1, ctx, fn };
        fn(&single_span);
        return;
    }
    if (nt > MAX_THREADS) nt = MAX_THREADS;

    pool_init(nt);

    if (g_pool_inited && g_pool.nt == nt) {
        pthread_mutex_lock(&g_pool_mu);
        g_pool.completed = 0;
        g_pool.generation++;
        for (int i = 0; i < nt; i++) {
            g_pool.slot[i].fn = fn;
            g_pool.slot[i].sp.t = i;
            g_pool.slot[i].sp.nt = nt;
            g_pool.slot[i].sp.ctx = ctx;
            g_pool.slot[i].sp.fn = fn;
            g_pool.slot[i].have_job = 1;
            g_pool.slot[i].done = 0;
        }
        pthread_cond_broadcast(&g_pool_cv_go);
        while (g_pool.completed < nt) pthread_cond_wait(&g_pool_cv_done, &g_pool_mu);
        pthread_mutex_unlock(&g_pool_mu);
        return;
    }

    pthread_t th[MAX_THREADS];
    span_t spans[MAX_THREADS];
    for (int i = 0; i < nt; i++) { spans[i].t = i; spans[i].nt = nt; spans[i].ctx = ctx; spans[i].fn = fn; }
    for (int i = 0; i < nt; i++) pthread_create(&th[i], 0, fn, &spans[i]);
    for (int i = 0; i < nt; i++) pthread_join(th[i], 0);
}

typedef struct { uint64_t s[4]; } rng_t;
static uint64_t splitmix(uint64_t *x) {
    uint64_t z = (*x += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}
static void rng_seed(rng_t *r, uint64_t seed) { for (int i = 0; i < 4; i++) r->s[i] = splitmix(&seed); }
static inline uint64_t rotl64(uint64_t x, int k) { return (x << k) | (x >> (64 - k)); }
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

typedef struct { int8_t *buf; int64_t total; uint64_t seed; } fill_ctx;
static void *fill_worker(void *a) {
    span_t *sp = a; fill_ctx *c = sp->ctx;
    int64_t lo = c->total * sp->t / sp->nt, hi = c->total * (sp->t + 1) / sp->nt;
    rng_t r; rng_seed(&r, c->seed + 0x9E37 * (uint64_t)(sp->t + 1));
    int64_t i = lo;
    while (i < hi) {
        uint64_t v = rng_next(&r);
        for (int b = 0; b < 8 && i < hi; b++, v >>= 8)
            c->buf[i++] = (int8_t)((uint8_t)v % 127) - 63;
    }
    return 0;
}

typedef struct { const int8_t *buf; int64_t len; const uint8_t *key; uint8_t *root; } mk_ctx;
static void *mk_worker(void *a) {
    mk_ctx *c = a;
    blake3_hasher h;
    blake3_hasher_init_keyed(&h, c->key);
#if defined(BLAKE3_USE_TBB)
    blake3_hasher_update_tbb(&h, c->buf, (size_t)c->len);
#else
    blake3_hasher_update(&h, c->buf, (size_t)c->len);
#endif
    blake3_hasher_finalize(&h, c->root, DIGEST);
    return 0;
}

typedef struct { uint8_t *out; int64_t nbytes; const uint8_t *seed, *key; int slot; } unif_ctx;
static void *unif_worker(void *a) {
    span_t *sp = a; unif_ctx *c = sp->ctx;
    int64_t draws = (c->nbytes + DIGEST - 1) / DIGEST;
    int64_t lo = draws * sp->t / sp->nt, hi = draws * (sp->t + 1) / sp->nt;
    for (int64_t i = lo; i < hi; i++) {
        uint8_t d[DIGEST];
        draw_hash((uint32_t)i, c->seed, c->key, c->slot, d);
        int64_t off = i * DIGEST, n = c->nbytes - off; if (n > DIGEST) n = DIGEST;
        memcpy(c->out + off, d, (size_t)n);
    }
    return 0;
}

typedef struct { uint8_t *raw; int8_t *out; int64_t n; } u2i_ctx;
static void *u2i_worker(void *a) {
    span_t *sp = a; u2i_ctx *c = sp->ctx;
    int64_t lo = c->n * sp->t / sp->nt, hi = c->n * (sp->t + 1) / sp->nt;
    int64_t i = lo;
    for (; i + 8 <= hi; i += 8) {
        for (int u = 0; u < 8; u++)
            c->out[i + u] = (int8_t)((c->raw[i + u] & RANGE_MASK) - ZERO_POINT);
    }
    for (; i < hi; i++) c->out[i] = (int8_t)((c->raw[i] & RANGE_MASK) - ZERO_POINT);
    return 0;
}

static void perm_pairs(const uint8_t *seed, const uint8_t *key, int64_t lines, int rank,
                       uint16_t *first, uint16_t *second) {
    int64_t draws = (lines * 4 + DIGEST - 1) / DIGEST;
    for (int64_t i = 0; i < draws; i++) {
        uint8_t d[DIGEST];
        draw_hash((uint32_t)i, seed, key, 1, d);
        for (int j = 0; j < 8; j++) {
            int64_t line = i * 8 + j; if (line >= lines) break;
            uint32_t u; memcpy(&u, d + j * 4, 4);
            uint32_t f = u & (uint32_t)(rank - 1);
            uint32_t s = f ^ (1u + (uint32_t)(((uint64_t)(rank - 1) * u) >> 32));
            first[line] = (uint16_t)f; second[line] = (uint16_t)s;
        }
    }
}

typedef struct { const int8_t *A, *EAL; int8_t *out; const uint16_t *f, *s;
                 int64_t m, k; int R; } an_ctx;
static void *an_worker(void *a) {
    span_t *sp = a; an_ctx *c = sp->ctx;
    int64_t lo = c->m * sp->t / sp->nt, hi = c->m * (sp->t + 1) / sp->nt;
    for (int64_t r = lo; r < hi; r++) {
        const int8_t *ar = c->A + r * c->k, *el = c->EAL + r * c->R;
        int8_t *o = c->out + r * c->k;
        __builtin_prefetch(ar + 64, 0, 1);
        __builtin_prefetch(el, 0, 1);
        for (int64_t j = 0; j < c->k; j++)
            o[j] = (int8_t)(ar[j] + el[c->f[j]] - el[c->s[j]]);
    }
    return 0;
}

typedef struct { const int8_t *B, *EBR; int8_t *out; const uint16_t *f, *s;
                 int64_t k, n; int R; } bn_ctx;
#define TB 64
static void *bn_worker(void *a) {
    span_t *sp = a; bn_ctx *c = sp->ctx;
    int64_t kb = (c->k + TB - 1) / TB;
    int64_t lo = kb * sp->t / sp->nt, hi = kb * (sp->t + 1) / sp->nt;
    for (int64_t ib = lo; ib < hi; ib++) {
        int64_t i0 = ib * TB, i1 = i0 + TB > c->k ? c->k : i0 + TB;
        for (int64_t j0 = 0; j0 < c->n; j0 += TB) {
            int64_t j1 = j0 + TB > c->n ? c->n : j0 + TB;
            for (int64_t j = j0; j < j1; j++) {
                const int8_t *bj = c->B + j * c->k, *ej = c->EBR + j * c->R;
                __builtin_prefetch(bj + i0 + 64, 0, 1);
                for (int64_t i = i0; i < i1; i++)
                    c->out[i * c->n + j] = (int8_t)(bj[i] + ej[c->f[i]] - ej[c->s[i]]);
            }
        }
    }
    return 0;
}

#define BN_PACK 64
typedef struct { const int8_t *B, *EBR; int8_t *bt; const uint16_t *f, *s;
                 int64_t k, n; int R; } bnp_ctx;
static void *bn_pack_worker(void *a) {
    span_t *sp = a; bnp_ctx *c = sp->ctx;
    int64_t nbands = c->n / BN_PACK, NFOLD = c->k / c->R;
    int64_t lo = nbands * sp->t / sp->nt, hi = nbands * (sp->t + 1) / sp->nt;
    for (int64_t jp = lo; jp < hi; jp++) {
        for (int64_t m = 0; m < BN_PACK; m++) {
            int64_t col = jp * BN_PACK + m;
            const int8_t *bcol = c->B + col * c->k;
            const int8_t *ecol = c->EBR + col * c->R;
            __builtin_prefetch(bcol, 0, 1);
            __builtin_prefetch(ecol, 0, 1);
            for (int64_t p = 0; p < NFOLD; p++) {
                int8_t *dst = c->bt + ((jp * NFOLD + p) * BN_PACK + m) * c->R;
                int64_t base = p * c->R;
                for (int64_t ki = 0; ki < c->R; ki++) {
                    int64_t row = base + ki;
                    dst[ki] = (int8_t)(bcol[row] + ecol[c->f[row]] - ecol[c->s[row]]);
                }
            }
        }
    }
    return 0;
}

static void unif_int8(const uint8_t *seed, const uint8_t *key, int64_t n, int8_t *out, int nt) {
    unif_ctx uc = { (uint8_t *)out, n, seed, key, 0 };
    run_threads(nt, unif_worker, &uc);
    u2i_ctx ic = { (uint8_t *)out, out, n };
    run_threads(nt, u2i_worker, &ic);
}

/* Reusable scratch for fA/sA/fB/sB, keyed by required k, to avoid malloc/free
 * on every call when k is stable across iterations (the common mining case). */
typedef struct {
    uint16_t *fA, *sA, *fB, *sB;
    int64_t cap;
} perm_scratch_t;

static __thread perm_scratch_t g_perm_scratch = {0};

static void perm_scratch_ensure(int64_t k) {
    if (g_perm_scratch.cap >= k) return;
    free(g_perm_scratch.fA); free(g_perm_scratch.sA);
    free(g_perm_scratch.fB); free(g_perm_scratch.sB);
    g_perm_scratch.fA = malloc((size_t)k * sizeof(uint16_t));
    g_perm_scratch.sA = malloc((size_t)k * sizeof(uint16_t));
    g_perm_scratch.fB = malloc((size_t)k * sizeof(uint16_t));
    g_perm_scratch.sB = malloc((size_t)k * sizeof(uint16_t));
    g_perm_scratch.cap = k;
}

static __thread uint16_t *g_fa_single = 0, *g_sa_single = 0;
static __thread int64_t g_single_cap = 0;
static void single_scratch_ensure(int64_t k) {
    if (g_single_cap >= k) return;
    free(g_fa_single); free(g_sa_single);
    g_fa_single = malloc((size_t)k * sizeof(uint16_t));
    g_sa_single = malloc((size_t)k * sizeof(uint16_t));
    g_single_cap = k;
}

static int prep_from_ab_impl(const int8_t *A, const int8_t *B, const uint8_t *key,
                 int64_t m, int64_t n, int64_t k, int R,
                 int8_t *A_noised, int8_t *Bt_out,
                 int8_t *EAL, int8_t *EBR,
                 uint8_t *rootA, uint8_t *rootB,
                 uint8_t *commitA, uint8_t *commitB,
                 int nt, int pack) {
    if ((m * k) % 1024 || (n * k) % 1024) return -1;
    if (k > (1 << 16)) return -2;

    mk_ctx ma = { A, m * k, key, rootA }, mb = { B, n * k, key, rootB };
    pthread_t t1, t2;
    pthread_create(&t1, 0, mk_worker, &ma);
    pthread_create(&t2, 0, mk_worker, &mb);
    pthread_join(t1, 0); pthread_join(t2, 0);

    blake3_hasher h;
    blake3_hasher_init(&h); blake3_hasher_update(&h, key, 32);
    blake3_hasher_update(&h, rootB, 32); blake3_hasher_finalize(&h, commitB, 32);
    blake3_hasher_init(&h); blake3_hasher_update(&h, commitB, 32);
    blake3_hasher_update(&h, rootA, 32); blake3_hasher_finalize(&h, commitA, 32);

    static const uint8_t seedA[32] = "A_tensor", seedB[32] = "B_tensor";
    unif_int8(seedA, commitA, m * R, EAL, nt);
    unif_int8(seedB, commitB, n * R, EBR, nt);

    perm_scratch_ensure(k);
    uint16_t *fA = g_perm_scratch.fA, *sA = g_perm_scratch.sA;
    uint16_t *fB = g_perm_scratch.fB, *sB = g_perm_scratch.sB;

    perm_pairs(seedA, commitA, k, R, fA, sA);
    perm_pairs(seedB, commitB, k, R, fB, sB);

    an_ctx ac = { A, EAL, A_noised, fA, sA, m, k, R };
    run_threads(nt, an_worker, &ac);
    if (pack) {
        bnp_ctx bp = { B, EBR, Bt_out, fB, sB, k, n, R };
        run_threads(nt, bn_pack_worker, &bp);
    } else {
        bn_ctx bc = { B, EBR, Bt_out, fB, sB, k, n, R };
        run_threads(nt, bn_worker, &bc);
    }

    return 0;
}

int prep_from_ab(const int8_t *A, const int8_t *B, const uint8_t *key,
                 int64_t m, int64_t n, int64_t k, int R,
                 int8_t *A_noised, int8_t *Bt_noised, int8_t *EAL, int8_t *EBR,
                 uint8_t *rootA, uint8_t *rootB, uint8_t *commitA, uint8_t *commitB, int nt) {
    return prep_from_ab_impl(A, B, key, m, n, k, R, A_noised, Bt_noised,
                             EAL, EBR, rootA, rootB, commitA, commitB, nt, 0);
}

static int prep_random_impl(uint64_t seed, int8_t *A, int8_t *B, const uint8_t *key,
                int64_t m, int64_t n, int64_t k, int R,
                int8_t *A_noised, int8_t *Bt_out, int8_t *EAL, int8_t *EBR,
                uint8_t *rootA, uint8_t *rootB, uint8_t *commitA, uint8_t *commitB,
                int nt, int pack) {
    fill_ctx fa = { A, m * k, seed }, fb = { B, n * k, seed ^ 0xB0B0B0B0ULL };
    run_threads(nt, fill_worker, &fa);
    run_threads(nt, fill_worker, &fb);
    return prep_from_ab_impl(A, B, key, m, n, k, R, A_noised, Bt_out,
                             EAL, EBR, rootA, rootB, commitA, commitB, nt, pack);
}

int prep_random(uint64_t seed, int8_t *A, int8_t *B, const uint8_t *key,
                int64_t m, int64_t n, int64_t k, int R,
                int8_t *A_noised, int8_t *Bt_noised, int8_t *EAL, int8_t *EBR,
                uint8_t *rootA, uint8_t *rootB, uint8_t *commitA, uint8_t *commitB, int nt) {
    return prep_random_impl(seed, A, B, key, m, n, k, R, A_noised, Bt_noised,
                            EAL, EBR, rootA, rootB, commitA, commitB, nt, 0);
}

int prep_random_bt(uint64_t seed, int8_t *A, int8_t *B, const uint8_t *key,
                int64_t m, int64_t n, int64_t k, int R,
                int8_t *A_noised, int8_t *bt_packed, int8_t *EAL, int8_t *EBR,
                uint8_t *rootA, uint8_t *rootB, uint8_t *commitA, uint8_t *commitB, int nt) {
    return prep_random_impl(seed, A, B, key, m, n, k, R, A_noised, bt_packed,
                            EAL, EBR, rootA, rootB, commitA, commitB, nt, 1);
}

int prep_b_side(uint64_t seed, int8_t *B, const uint8_t *key,
                int64_t n, int64_t k, int R,
                int8_t *bt_packed, int8_t *EBR, uint8_t *rootB, uint8_t *commitB, int nt) {
    if ((n * k) % 1024) return -1;
    if (k > (1 << 16)) return -2;
    fill_ctx fb = { B, n * k, seed };
    run_threads(nt, fill_worker, &fb);
    mk_ctx mb = { B, n * k, key, rootB };
    pthread_t t; pthread_create(&t, 0, mk_worker, &mb); pthread_join(t, 0);
    blake3_hasher h;
    blake3_hasher_init(&h); blake3_hasher_update(&h, key, 32);
    blake3_hasher_update(&h, rootB, 32); blake3_hasher_finalize(&h, commitB, 32);
    static const uint8_t seedB[32] = "B_tensor";
    unif_int8(seedB, commitB, n * R, EBR, nt);

    perm_scratch_ensure(k);
    uint16_t *fB = g_perm_scratch.fB, *sB = g_perm_scratch.sB;
    perm_pairs(seedB, commitB, k, R, fB, sB);

    bnp_ctx bp = { B, EBR, bt_packed, fB, sB, k, n, R };
    run_threads(nt, bn_pack_worker, &bp);

    return 0;
}

int prep_a_side(uint64_t seed, int8_t *A, const uint8_t *key, const uint8_t *commitB,
                int64_t m, int64_t k, int R,
                int8_t *A_noised, int8_t *EAL, uint8_t *rootA, uint8_t *commitA, int nt) {
    if ((m * k) % 1024) return -1;
    if (k > (1 << 16)) return -2;
    fill_ctx fa = { A, m * k, seed };
    run_threads(nt, fill_worker, &fa);
    mk_ctx ma = { A, m * k, key, rootA };
    pthread_t t; pthread_create(&t, 0, mk_worker, &ma); pthread_join(t, 0);
    blake3_hasher h;
    blake3_hasher_init(&h); blake3_hasher_update(&h, commitB, 32);
    blake3_hasher_update(&h, rootA, 32); blake3_hasher_finalize(&h, commitA, 32);
    static const uint8_t seedA[32] = "A_tensor";
    unif_int8(seedA, commitA, m * R, EAL, nt);

    single_scratch_ensure(k);
    uint16_t *fA = g_fa_single, *sA = g_sa_single;
    perm_pairs(seedA, commitA, k, R, fA, sA);

    an_ctx ac = { A, EAL, A_noised, fA, sA, m, k, R };
    run_threads(nt, an_worker, &ac);

    return 0;
}
