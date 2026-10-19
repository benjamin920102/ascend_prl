/* Pool-independent miner: overlaps preparation and NPU scanning, with optional B reuse.
 * Usage: ascend_prl_<pool> <devid> <worker> <host> <port> <address> <password>
 */
#include "pools/pool.h"
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define R 128

extern int pearl_init(int dev, int nbands);
extern void pearl_set_b(const int8_t *b, int n);
extern void pearl_set_b_slot(const int8_t *b, int n, int slot) __attribute__((weak));
extern void pearl_use_b(int slot) __attribute__((weak));
extern void pearl_set_bt_slot(const int8_t *bt, int slot) __attribute__((weak));
extern int prep_b_side(uint64_t seed, int8_t *B, const uint8_t *key,
                       int64_t n, int64_t k, int rank,
                       int8_t *bt_packed, int8_t *EBR, uint8_t *rootB, uint8_t *commitB, int nt, int cert_version);
extern int pearl_prep_a_device(int slot, uint64_t seed, const uint8_t *key,
    const uint8_t *commitB, int64_t m, int64_t k, int rank, int nt, int cert,
    uint8_t *rootA, uint8_t *commitA);
extern void pearl_use_a_device(int slot);
extern void pearl_read_a_device(int slot, int8_t *host);
extern int scan_full(const int8_t *an, int nstrips, const uint8_t *key, const uint32_t *tgt,
                     int nbands, int n_hi, int pow_threads, uint32_t *scratch,
                     int *hs, int *ht);
extern ssize_t build_proof_b64(const uint8_t *a, const uint8_t *b, size_t m, size_t n,
                               size_t k, size_t rank, const uint8_t *key,
                               const size_t *ar, size_t na, const size_t *bc, size_t nb,
                               uint8_t *out, size_t cap);
extern int hash_key(const uint8_t *hdr, size_t hl, size_t k, size_t rank,
                    const size_t *rp, size_t nr, const size_t *cp, size_t nc, uint8_t *out);
extern ssize_t gzip_proof_b64(const char *in_b64, size_t in_len, uint8_t *out, size_t cap);

static pool_conn_t user_conn;
static job_t *g_job = &user_conn.job;
static mining_params_t mp;

static int do_handshake(const char *host, int port, const char *addr,
                        const char *worker, const char *pass) {
    user_conn.msg_id = 0; user_conn.job.have = 0;
    if (!POOL.miner_chosen_params) mp.have = 0;
    if (POOL.open(&user_conn, host, port, addr, worker, pass, &mp)) return -1;
    for (int i = 0; i < 300; i++) {
        int ok;
        pthread_mutex_lock(&job_mu); ok = user_conn.job.have; pthread_mutex_unlock(&job_mu);
        if (ok && mp.have) break;
        usleep(100000);
    }
    if (!(user_conn.job.have && mp.have)) {
        pool_stop_reader(&user_conn);
        return -1;
    }
    printf("[stratum] ready (pool=%s rank=%ld k=%ld %ldx%ld)\n",
           POOL.name, mp.rank, mp.k, mp.m, mp.n);
    return 0;
}

typedef struct {
    int8_t *A, *B, *Btn, *EBR;
    uint8_t roots[4][32];
    uint8_t key[32];
    char job_id[JOBLEN];
    double diff;
    uint8_t ptarget[32];
    int cert_version;
    int slot;
    int proof_busy, hit_strip, hit_tile;
} bundle_t;
static void bundle_key(bundle_t *b);
static _Atomic long g_last_scan_ms = 0, g_last_prep_ms = 0;

/* One bounded proof worker borrows a bundle until submission completes. Prep
 * waits only when reusing that bundle; no full-matrix snapshot is needed. */
static pthread_mutex_t proof_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t proof_cv = PTHREAD_COND_INITIALIZER;
static bundle_t *proof_queue[2];
static int proof_head, proof_count, proof_active, proof_stop;
static pthread_t proof_thread;
static const char *submit_addr, *submit_worker;
static void proof_drain(void) {
    pthread_mutex_lock(&proof_mu);
    while (proof_count || proof_active) pthread_cond_wait(&proof_cv, &proof_mu);
    pthread_mutex_unlock(&proof_mu);
}
static void proof_wait_bundle(bundle_t *b) {
    pthread_mutex_lock(&proof_mu);
    while (b->proof_busy) pthread_cond_wait(&proof_cv, &proof_mu);
    pthread_mutex_unlock(&proof_mu);
}
static double monotonic_ms(void) {
    struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1e3 + t.tv_nsec / 1e6;
}
static void *proof_worker(void *unused);
static void start_prep(pthread_t *thread, bundle_t *b);
static void prep_check(int rc) {
    if (rc) { fprintf(stderr, "[!] matrix preparation failed: %d\n", rc); exit(2); }
}
static void proof_enqueue(bundle_t *b, int hs, int ht) {
    pthread_mutex_lock(&proof_mu);
    while (proof_count == 2) pthread_cond_wait(&proof_cv, &proof_mu);
    b->hit_strip = hs; b->hit_tile = ht; b->proof_busy = 1;
    proof_queue[(proof_head + proof_count++) % 2] = b;
    pthread_cond_broadcast(&proof_cv);
    pthread_mutex_unlock(&proof_mu);
}

static int g_reuse_b = 0;
static struct {
    int8_t *B, *bt;
    int8_t *EBR;
    uint8_t key[32], commitB[32], rootB[32];
    char job_id[JOBLEN];
    double diff; uint8_t ptarget[32];
    int cert_version;
    int slot, valid; long since;
} bs;

// Refresh the cached B commitment on job changes or after PRL_BREUSE iterations.
// The matching A side must use this exact B commitment to build valid proofs.
static int ensure_bside(long N, long Kc, int rank, int prep_n) {
    long refresh = getenv("PRL_BREUSE") ? atol(getenv("PRL_BREUSE")) : 0;
    pthread_mutex_lock(&job_mu);
    int jobchg = !bs.valid || strncmp(bs.job_id, g_job->job_id, JOBLEN - 1);
    char jid[JOBLEN]; strncpy(jid, g_job->job_id, JOBLEN - 1); jid[JOBLEN - 1] = 0;
    double diff = g_job->difficulty; uint8_t pt[32]; memcpy(pt, g_job->ptarget, 32);
    int cert_version = g_job->cert_version;
    static uint8_t hdr[HDRLEN]; size_t hl = g_job->header_len; memcpy(hdr, g_job->header, hl);
    pthread_mutex_unlock(&job_mu);
    if (!(jobchg || (refresh > 0 && bs.since >= refresh))) return 0;
    // Cached B must remain immutable while a queued proof borrows it.
    proof_drain();
    snprintf(bs.job_id, JOBLEN, "%s", jid); bs.diff = diff; memcpy(bs.ptarget, pt, 32);
    bs.cert_version = cert_version;
    hash_key(hdr, hl, (size_t)Kc, (size_t)rank, mp.rows, mp.nrows, mp.cols, mp.ncols, bs.key);
    uint64_t seed = ((uint64_t)rand() << 32) ^ (uint64_t)time(0) ^ 0xB5B5ULL;
    prep_check(prep_b_side(seed, bs.B, bs.key, N, Kc, rank, bs.bt, bs.EBR, bs.rootB, bs.commitB, prep_n, cert_version));
    if (pearl_set_bt_slot)     pearl_set_bt_slot(bs.bt, 0);
    else if (pearl_set_b_slot) pearl_set_b_slot(bs.bt, (int)N, 0);
    bs.slot = 0; bs.valid = 1; bs.since = 0;
    return 1;
}

static void *prep_worker(void *p) {
    bundle_t *b = p;
    double wait_start = monotonic_ms();
    proof_wait_bundle(b);
    if (getenv("PRL_LOOP_PROF")) fprintf(stderr, "[prepprof] proof-hold=%.1fms\n", monotonic_ms()-wait_start);
    if (g_reuse_b) {
        int prep_n = getenv("PRL_PREP_THREADS") ? atoi(getenv("PRL_PREP_THREADS")) : 64;
        struct timespec pa, pb; clock_gettime(CLOCK_MONOTONIC, &pa);
        uint64_t seed = ((uint64_t)rand() << 32) ^ (uint64_t)time(0);
        snprintf(b->job_id, JOBLEN, "%s", bs.job_id);
        b->diff = bs.diff; memcpy(b->ptarget, bs.ptarget, 32); memcpy(b->key, bs.key, 32);
        b->cert_version = bs.cert_version;
        prep_check(pearl_prep_a_device(b->slot, seed, bs.key, bs.commitB, mp.m, mp.k,
                    (int)mp.rank, prep_n, bs.cert_version, b->roots[0], b->roots[2]));
        clock_gettime(CLOCK_MONOTONIC, &pb);
        g_last_prep_ms = (pb.tv_sec - pa.tv_sec) * 1000 + (pb.tv_nsec - pa.tv_nsec) / 1000000;
        return 0;
    }
    const char *ds = getenv("PRL_PREP_DELAY_MS");
    // Start immediately unless an explicit delay is requested for CPU tuning.
    long delay_ms = ds ? atol(ds) : 0;
    if (delay_ms > 0) {
        struct timespec delay = {delay_ms / 1000, (delay_ms % 1000) * 1000000};
        while (nanosleep(&delay, &delay) && errno == EINTR) {}
    }
    bundle_key(b);
    struct timespec pa, pb;
    clock_gettime(CLOCK_MONOTONIC, &pa);
    uint64_t seed = ((uint64_t)rand() << 32) ^ (uint64_t)time(0);
    int prep_n = getenv("PRL_PREP_THREADS") ? atoi(getenv("PRL_PREP_THREADS")) : 64;
    prep_check(prep_b_side(seed ^ 0xB0B0B0B0ULL, b->B, b->key, mp.n, mp.k,
                (int)mp.rank, b->Btn, b->EBR, b->roots[1], b->roots[3], prep_n, b->cert_version));
    prep_check(pearl_prep_a_device(b->slot, seed, b->key, b->roots[3], mp.m, mp.k,
                (int)mp.rank, prep_n, b->cert_version, b->roots[0], b->roots[2]));
    clock_gettime(CLOCK_MONOTONIC, &pb);
    g_last_prep_ms = (pb.tv_sec - pa.tv_sec) * 1000 + (pb.tv_nsec - pa.tv_nsec) / 1000000;
    if (pearl_set_bt_slot)     pearl_set_bt_slot(b->Btn, b->slot);
    else if (pearl_set_b_slot) pearl_set_b_slot(b->Btn, (int)mp.n, b->slot);
    return 0;
}

static void start_prep(pthread_t *thread, bundle_t *b) {
    if (pthread_create(thread, 0, prep_worker, b)) {
        fputs("[!] cannot start prep worker\n", stderr); exit(2);
    }
}

static void bundle_key(bundle_t *b) {
    pthread_mutex_lock(&job_mu);
    snprintf(b->job_id, JOBLEN, "%s", g_job->job_id);
    b->diff = g_job->difficulty;
    b->cert_version = g_job->cert_version;
    memcpy(b->ptarget, g_job->ptarget, 32);
    hash_key(g_job->header, g_job->header_len, (size_t)mp.k, (size_t)mp.rank,
             mp.rows, mp.nrows, mp.cols, mp.ncols, b->key);
    pthread_mutex_unlock(&job_mu);
}

// SIGUSR1 requests a pause; acknowledge only after the current NPU scan is done.
// SIGUSR2 lets the loop resume without interrupting an in-flight kernel.
static volatile sig_atomic_t g_pause_req = 0;
static volatile sig_atomic_t g_ack_pid = 0;
static void on_pause_sig(int sig, siginfo_t *si, void *u) {
    (void)sig; (void)u;
    g_pause_req = 1;
    g_ack_pid = si ? (sig_atomic_t)si->si_pid : 0;
}
static void on_resume_sig(int sig, siginfo_t *si, void *u) {
    (void)sig; (void)si; (void)u;
    g_pause_req = 0;
}
static void coexist_gate(void) {
    if (!g_pause_req) return;
    pid_t ack = (pid_t)g_ack_pid;
    printf("[coexist] pause (req pid %d): NPU quiescent, idling until resume\n", (int)ack);
    if (ack > 0) kill(ack, SIGUSR1);
    while (g_pause_req) {
        struct timespec ts = {0, 200L * 1000 * 1000};
        nanosleep(&ts, 0);
    }
    puts("[coexist] resume");
}

static void process_proof(bundle_t *cur, uint8_t *b64, uint8_t *gzbuf) {
    long M = mp.m, N = mp.n, Kc = mp.k;
    int nbands = (int)(N / 64), ht_per_block = 64 / (int)mp.nrows;
    size_t rows_abs[64], cols_abs[64];
    // Decode the vector kernel's tile index into the logical row/column origin.
    int hi = cur->hit_tile / nbands, wi = cur->hit_tile % nbands;
    long row = (long)cur->hit_strip * R + (long)(hi / ht_per_block) * 64 + hi % ht_per_block;
    long col = (long)wi * 64;
    for (size_t i = 0; i < mp.nrows; i++) rows_abs[i] = (size_t)row + mp.rows[i];
    for (size_t i = 0; i < mp.ncols; i++) cols_abs[i] = (size_t)col + mp.cols[i];
    double proof_start = monotonic_ms();
    pearl_read_a_device(cur->slot, cur->A);
    ssize_t bl = build_proof_b64((uint8_t *)cur->A, (uint8_t *)(g_reuse_b ? bs.B : cur->B),
                                 (size_t)M, (size_t)N, (size_t)Kc, (size_t)mp.rank,
                                 cur->key, rows_abs, mp.nrows, cols_abs, mp.ncols,
                                 b64, 64 << 20);
    double proof_end = monotonic_ms();
    if (bl > 0) {
        pool_conn_t *sc = &user_conn;
        const char *sub_addr = submit_addr;
        const uint8_t *payload = b64; size_t plen = (size_t)bl;
        pool_conn_t prefix_conn = {0};
        prefix_conn.gzip = sc->gzip;
        if (prefix_conn.gzip) {
            ssize_t gl = gzip_proof_b64((const char *)b64, (size_t)bl, gzbuf, 64 << 20);
            if (gl > 0) { payload = gzbuf; plen = (size_t)gl; }
            else { printf("[!] gzip proof failed (%zd), dropping share\n", gl); plen = 0; }
        }
        double gzip_end = monotonic_ms();
        // Snapshot gzip negotiation for both payload and prefix. The reader
        // may negotiate it while proof construction is running.
        if (!plen || sc->dead) return;
        pthread_mutex_lock(&job_mu);
        int stale = strncmp(cur->job_id, g_job->job_id, JOBLEN) != 0;
        pthread_mutex_unlock(&job_mu);
        if (stale) { puts("[proof] stale job, discarding share"); return; }
        char *msg = malloc(plen + 512);
        if (!msg) {
            fputs("[!] cannot allocate share message\n", stderr);
        } else {
            prefix_conn.msg_id = atomic_fetch_add(&sc->msg_id, 1);
            const char *tail;
            int hl = POOL.submit_prefix(&prefix_conn, sub_addr, submit_worker, cur->job_id, msg, 512, &tail);
            if (hl < 0 || hl >= 512) {
                fputs("[!] share prefix exceeds message capacity\n", stderr);
            } else {
                size_t tail_len = strlen(tail);
                if ((size_t)hl + tail_len + 1 > 512) {
                    fputs("[!] share suffix exceeds message capacity\n", stderr);
                } else {
                    memcpy(msg + hl, payload, plen);
                    memcpy(msg + hl + plen, tail, tail_len + 1);
                    // The proof length is already known; avoid scanning it with strlen.
                    int sent = pool_send_line_checked(sc, msg, (size_t)hl + plen + tail_len);
                    if (getenv("PRL_RAW")) fprintf(stderr, "[raw>] %s\n", msg);
                    if (getenv("PRL_LOOP_PROF")) fprintf(stderr,
                        "[proofprof] proof=%.1fms gzip=%.1fms send=%.1fms\n",
                        proof_end-proof_start, gzip_end-proof_end, monotonic_ms()-gzip_end);
                    if (sent) { fputs("[!] share send failed\n", stderr); free(msg); return; }
                    shares_sub++;
                    printf("[✓] share row=%ld col=%ld job=%s (%ld submitted)\n",
                           row, col, cur->job_id, shares_sub);
                }
            }
            free(msg);
        }
    } else printf("[!] proof build failed %zd\n", bl);
}

static void *proof_worker(void *unused) {
    (void)unused;
    uint8_t *b64 = malloc(64 << 20), *gzbuf = malloc(64 << 20);
    if (!b64 || !gzbuf) { fputs("[!] proof buffer allocation failed\n", stderr); exit(2); }
    for (;;) {
        pthread_mutex_lock(&proof_mu);
        while (!proof_count && !proof_stop) pthread_cond_wait(&proof_cv, &proof_mu);
        if (!proof_count && proof_stop) { pthread_mutex_unlock(&proof_mu); break; }
        bundle_t *b = proof_queue[proof_head];
        proof_head = (proof_head + 1) % 2; --proof_count; proof_active = 1;
        pthread_cond_broadcast(&proof_cv);
        pthread_mutex_unlock(&proof_mu);
        struct timespec a, z; clock_gettime(CLOCK_MONOTONIC, &a);
        process_proof(b, b64, gzbuf);
        clock_gettime(CLOCK_MONOTONIC, &z);
        if (getenv("PRL_LOOP_PROF")) fprintf(stderr, "[proofprof] proof+gzip+send=%.1fms\n",
            (z.tv_sec-a.tv_sec)*1e3 + (z.tv_nsec-a.tv_nsec)/1e6);
        pthread_mutex_lock(&proof_mu);
        b->proof_busy = 0; proof_active = 0;
        pthread_cond_broadcast(&proof_cv);
        pthread_mutex_unlock(&proof_mu);
    }
    free(b64); free(gzbuf); return 0;
}

int main(int argc, char **argv) {
    if (argc < 7) { fprintf(stderr, "usage: %s dev worker host port addr pass\n", argv[0]); return 1; }
    int dev = atoi(argv[1]);
    const char *worker = argv[2], *host = argv[3], *addr = argv[5], *pass = argv[6];
    int port = atoi(argv[4]);
    signal(SIGPIPE, SIG_IGN);
    {
        struct sigaction sa;
        memset(&sa, 0, sizeof sa);
        sa.sa_flags = SA_SIGINFO | SA_RESTART;
        sigemptyset(&sa.sa_mask);
        sa.sa_sigaction = on_pause_sig;
        sigaction(SIGUSR1, &sa, 0);
        sa.sa_sigaction = on_resume_sig;
        sigaction(SIGUSR2, &sa, 0);
    }
    setvbuf(stdout, 0, _IOLBF, 0);
    g_reuse_b = getenv("PRL_REUSE_B") ? 1 : 0;
    pool_conn_init(&user_conn, "");

    POOL.init_params(&mp);
    printf("[stratum] pool=%s\n", POOL.name);

    while (do_handshake(host, port, addr, worker, pass)) { puts("[!] handshake failed, retry 10s"); sleep(10); }

    long M = mp.m, N = mp.n, Kc = mp.k;
    int nbands = (int)(N / 64), nstrips = (int)(M / R);
    int tile_h = (int)mp.nrows, n_hi = R / tile_h;
    if (pearl_init(dev, nbands)) { puts("pearl_init failed"); return 2; }

    extern void *pearl_pinned_alloc(size_t) __attribute__((weak));
    bundle_t bun[2] = {0};
    for (int i = 0; i < 2; i++) {
        bun[i].slot = i;
        bun[i].A = malloc((size_t)M * Kc); bun[i].B = malloc((size_t)N * Kc);
        bun[i].Btn = pearl_pinned_alloc ? pearl_pinned_alloc((size_t)Kc * N)
                                       : malloc((size_t)Kc * N);
        bun[i].EBR = malloc((size_t)N * mp.rank);
    }
    for (int i = 0; i < 2; ++i) {
        if (!bun[i].A || !bun[i].B || !bun[i].Btn || !bun[i].EBR) {
            fputs("[!] bundle allocation failed\n", stderr); return 2;
        }
    }
    uint32_t *scratch = malloc(2ull * nbands * 16 * 64 * 4);
    if (!scratch) { fputs("[!] scratch allocation failed\n", stderr); return 2; }
    submit_addr = addr; submit_worker = worker;
    if (pthread_create(&proof_thread, 0, proof_worker, 0)) {
        fputs("[!] cannot start proof worker\n", stderr); return 2;
    }

    if (g_reuse_b) {
        bs.B = malloc((size_t)N * Kc); bs.bt = pearl_pinned_alloc ? pearl_pinned_alloc((size_t)Kc * N) : malloc((size_t)Kc * N);
        bs.EBR = malloc((size_t)N * mp.rank); bs.valid = 0;
        if (!bs.B || !bs.bt || !bs.EBR) {
            fputs("[!] reuse-B allocation failed\n", stderr); exit(2);
        }
        ensure_bside(N, Kc, (int)mp.rank, 64);
        printf("[reuse-B] enabled (PRL_BREUSE=%s, B-side cached per job)\n",
               getenv("PRL_BREUSE") ? getenv("PRL_BREUSE") : "0=job-change-only");
    }
    pthread_t pt;
    start_prep(&pt, &bun[0]);
    long iter = 0;
    time_t t_start = time(0);
    while (1) {
        if (user_conn.dead) {
            proof_drain(); // No proof may send through a replaced pool session.
            puts("[!] (re)connecting");
            pool_stop_reader(&user_conn);
            while (do_handshake(host, port, addr, worker, pass)) sleep(10);
        }
        // Two bundles let CPU preparation and B transfer overlap NPU scanning.
        bundle_t *cur = &bun[iter % 2], *nxt = &bun[(iter + 1) % 2];
        struct timespec lj0; clock_gettime(CLOCK_MONOTONIC, &lj0);
        pthread_join(pt, 0);
        struct timespec lj1; clock_gettime(CLOCK_MONOTONIC, &lj1);
        coexist_gate();
        if (g_reuse_b) {
            // A fresh B side invalidates the A prepared against the previous commitment.
            int prep_n = getenv("PRL_PREP_THREADS") ? atoi(getenv("PRL_PREP_THREADS")) : 64;
            if (ensure_bside(N, Kc, (int)mp.rank, prep_n)) {
                uint64_t s = ((uint64_t)rand() << 32) ^ (uint64_t)time(0) ^ 0xA5A5ULL;
                prep_check(pearl_prep_a_device(cur->slot, s, bs.key, bs.commitB, mp.m, mp.k,
                            (int)mp.rank, prep_n, bs.cert_version, cur->roots[0], cur->roots[2]));
                snprintf(cur->job_id, JOBLEN, "%s", bs.job_id);
                cur->diff = bs.diff; memcpy(cur->ptarget, bs.ptarget, 32); memcpy(cur->key, bs.key, 32);
                cur->cert_version = bs.cert_version;
            }
            bs.since++;
        }
        start_prep(&pt, nxt);

        time_t t0 = time(0);
        struct timespec sa; clock_gettime(CLOCK_MONOTONIC, &sa);
        if (pearl_use_b) pearl_use_b(g_reuse_b ? 0 : cur->slot);
        else pearl_set_b(cur->Btn, (int)N);
        uint32_t tgt[8];
        long rounded_k = (Kc / mp.rank) * mp.rank;
        job_t jt; jt.difficulty = cur->diff; memcpy(jt.ptarget, cur->ptarget, 32);
        POOL.build_target(&jt, tile_h, rounded_k, tgt);
        struct timespec sbb; clock_gettime(CLOCK_MONOTONIC, &sbb);
        int hs = -1, ht = -1;
        int pow_n = getenv("PRL_POW_THREADS") ? atoi(getenv("PRL_POW_THREADS")) : 64;
        pearl_use_a_device(cur->slot);
        int rc = scan_full(NULL, nstrips, cur->roots[2], tgt, nbands, n_hi, pow_n,
                           scratch, &hs, &ht);
        struct timespec sb; clock_gettime(CLOCK_MONOTONIC, &sb);
        g_last_scan_ms = (sb.tv_sec - sa.tv_sec) * 1000 + (sb.tv_nsec - sa.tv_nsec) / 1000000;
        if (getenv("PRL_LOOP_PROF"))
            fprintf(stderr, "[loopprof] prep-join=%.0fms set_b+tgt=%.0fms scan_full=%.0fms\n",
                    (lj1.tv_sec-lj0.tv_sec)*1e3 + (lj1.tv_nsec-lj0.tv_nsec)/1e6,
                    (sbb.tv_sec-sa.tv_sec)*1e3 + (sbb.tv_nsec-sa.tv_nsec)/1e6,
                    (sb.tv_sec-sbb.tv_sec)*1e3 + (sb.tv_nsec-sbb.tv_nsec)/1e6);
        iter++;
        if (rc) proof_enqueue(cur, hs, ht);
        double el = difftime(time(0), t_start);
        printf("[*] iter %ld scan %.0fs%s | %.3f iter/s | shares %ld/%ld\n",
               iter, difftime(time(0), t0), rc ? " HIT" : "", iter / (el > 0 ? el : 1), shares_acc, shares_sub);
        {
            const char *mi = getenv("PRL_MAX_ITERS");
            if (mi && iter >= atol(mi)) {
                puts("[*] PRL_MAX_ITERS reached, exiting");
                break;
            }
        }
    }
    pthread_join(pt, 0);
    proof_drain();
    pthread_mutex_lock(&proof_mu); proof_stop = 1;
    pthread_cond_broadcast(&proof_cv); pthread_mutex_unlock(&proof_mu);
    pthread_join(proof_thread, 0);
    pool_stop_reader(&user_conn);
    return 0;
}
