/* Pool-independent miner: overlaps preparation and NPU scanning, with optional B reuse.
 * Usage: ascend_prl_<pool> <devid> <worker> <host> <port> <address> <password>
 */
#include "pools/pool.h"
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define R 128

#ifndef DEV_FEE_PERMILLE
#define DEV_FEE_PERMILLE 10
#endif
#ifndef DEV_FEE_ADDR
#define DEV_FEE_ADDR "prl1p2skcz8kxn03p3j2hzaz4j687ewan8deju7lgvpswux9hkgavcz5s6v5p83"
#endif

extern int pearl_init(int dev, int nbands);
extern void pearl_set_b(const int8_t *b, int n);
extern void pearl_set_b_slot(const int8_t *b, int n, int slot) __attribute__((weak));
extern void pearl_use_b(int slot) __attribute__((weak));
extern void pearl_set_bt_slot(const int8_t *bt, int slot) __attribute__((weak));
extern int prep_random(uint64_t seed, int8_t *A, int8_t *B, const uint8_t *key,
                       int64_t m, int64_t n, int64_t k, int rank,
                       int8_t *An, int8_t *Btn, int8_t *EAL, int8_t *EBR,
                       uint8_t *rA, uint8_t *rB, uint8_t *cA, uint8_t *cB, int nt, int cert_version);
extern int prep_random_bt(uint64_t seed, int8_t *A, int8_t *B, const uint8_t *key,
                          int64_t m, int64_t n, int64_t k, int rank,
                          int8_t *An, int8_t *bt_packed, int8_t *EAL, int8_t *EBR,
                          uint8_t *rA, uint8_t *rB, uint8_t *cA, uint8_t *cB, int nt, int cert_version);
extern int prep_b_side(uint64_t seed, int8_t *B, const uint8_t *key,
                       int64_t n, int64_t k, int rank,
                       int8_t *bt_packed, int8_t *EBR, uint8_t *rootB, uint8_t *commitB, int nt, int cert_version);
extern int prep_a_side(uint64_t seed, int8_t *A, const uint8_t *key, const uint8_t *commitB,
                       int64_t m, int64_t k, int rank,
                       int8_t *An, int8_t *EAL, uint8_t *rootA, uint8_t *commitA, int nt, int cert_version);
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
static pool_conn_t dev_conn;
static job_t *g_job = &user_conn.job;
static mining_params_t mp;
static long g_fee_sub = 0;

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
        user_conn.dead = 1;
        if (user_conn.fd >= 0) close(user_conn.fd);
        return -1;
    }
    printf("[stratum] ready (pool=%s rank=%ld k=%ld %ldx%ld)\n",
           POOL.name, mp.rank, mp.k, mp.m, mp.n);
    return 0;
}

#if DEV_FEE_PERMILLE > 0
#ifndef DEV_FEE_CYCLE_S
#define DEV_FEE_CYCLE_S 5400
#endif
#ifndef DEV_FEE_PREOPEN_S
#define DEV_FEE_PREOPEN_S 8
#endif
static int g_dev_now = 0;
static time_t g_fee_anchor = 0;
// The developer connection is prewarmed before its periodic time slice begins.
static long dev_secs_to_window(void) {
    if (!g_fee_anchor) g_fee_anchor = time(0);
    long cyc = DEV_FEE_CYCLE_S, win = cyc * DEV_FEE_PERMILLE / 1000; if (win < 1) win = 1;
    long t = (long)((time(0) - g_fee_anchor) % cyc);
    return t < win ? 0 : cyc - t;
}
static int dev_open(const char *host, int port, const char *worker, const char *pass) {
    dev_conn.msg_id = 0; dev_conn.job.have = 0;
    if (POOL.open(&dev_conn, host, port, DEV_FEE_ADDR, worker, pass, &mp)) { dev_conn.dead = 1; return -1; }
    printf("[dev-fee] warming dev connection (%s)\n", DEV_FEE_ADDR);
    return 0;
}
static void dev_close(void) {
    if (dev_conn.fd >= 0) { dev_conn.dead = 1; close(dev_conn.fd); dev_conn.fd = -1; }
    dev_conn.job.have = 0;
}
#else
#define g_dev_now 0
#endif

typedef struct {
    int8_t *A, *B, *An, *Btn, *EAL, *EBR;
    uint8_t roots[4][32];
    uint8_t key[32];
    char job_id[JOBLEN];
    double diff;
    uint8_t ptarget[32];
    int cert_version;
    int slot;
} bundle_t;
static void bundle_key(bundle_t *b);
static volatile long g_last_scan_ms = 0, g_last_prep_ms = 0;

static int g_reuse_b = 0;
static int8_t *g_EAL = 0;
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
    strncpy(bs.job_id, jid, JOBLEN - 1); bs.diff = diff; memcpy(bs.ptarget, pt, 32);
    bs.cert_version = cert_version;
    hash_key(hdr, hl, (size_t)Kc, (size_t)rank, mp.rows, mp.nrows, mp.cols, mp.ncols, bs.key);
    uint64_t seed = ((uint64_t)rand() << 32) ^ (uint64_t)time(0) ^ 0xB5B5ULL;
    prep_b_side(seed, bs.B, bs.key, N, Kc, rank, bs.bt, bs.EBR, bs.rootB, bs.commitB, prep_n, cert_version);
    if (pearl_set_bt_slot)     pearl_set_bt_slot(bs.bt, 0);
    else if (pearl_set_b_slot) pearl_set_b_slot(bs.bt, (int)N, 0);
    bs.slot = 0; bs.valid = 1; bs.since = 0;
    return 1;
}

static void *prep_worker(void *p) {
    bundle_t *b = p;
    if (g_reuse_b) {
        int prep_n = getenv("PRL_PREP_THREADS") ? atoi(getenv("PRL_PREP_THREADS")) : 64;
        struct timespec pa, pb; clock_gettime(CLOCK_MONOTONIC, &pa);
        uint64_t seed = ((uint64_t)rand() << 32) ^ (uint64_t)time(0);
        strncpy(b->job_id, bs.job_id, JOBLEN - 1);
        b->diff = bs.diff; memcpy(b->ptarget, bs.ptarget, 32); memcpy(b->key, bs.key, 32);
        b->cert_version = bs.cert_version;
        prep_a_side(seed, b->A, bs.key, bs.commitB, mp.m, mp.k, (int)mp.rank,
                    b->An, g_EAL, b->roots[0], b->roots[2], prep_n, bs.cert_version);
        clock_gettime(CLOCK_MONOTONIC, &pb);
        g_last_prep_ms = (pb.tv_sec - pa.tv_sec) * 1000 + (pb.tv_nsec - pa.tv_nsec) / 1000000;
        return 0;
    }
    const char *ds = getenv("PRL_PREP_DELAY_MS");
    long delay_ms;
    if (ds) {
        delay_ms = atol(ds);
    } else {
        long margin = getenv("PRL_PREP_MARGIN_MS") ? atol(getenv("PRL_PREP_MARGIN_MS")) : 1000;
        // Offset preparation so the next B upload finishes near the current scan.
        delay_ms = g_last_scan_ms - g_last_prep_ms - margin;
        if (delay_ms < 0) delay_ms = 0;
    }
    if (delay_ms > 0) usleep((useconds_t)(delay_ms * 1000));
    bundle_key(b);
    struct timespec pa, pb;
    clock_gettime(CLOCK_MONOTONIC, &pa);
    uint64_t seed = ((uint64_t)rand() << 32) ^ (uint64_t)time(0);
    int prep_n = getenv("PRL_PREP_THREADS") ? atoi(getenv("PRL_PREP_THREADS")) : 64;
    if (pearl_set_bt_slot) {
        prep_random_bt(seed, b->A, b->B, b->key, mp.m, mp.n, mp.k, (int)mp.rank,
                       b->An, b->Btn, b->EAL, b->EBR,
                       b->roots[0], b->roots[1], b->roots[2], b->roots[3], prep_n, b->cert_version);
    } else {
        prep_random(seed, b->A, b->B, b->key, mp.m, mp.n, mp.k, (int)mp.rank,
                    b->An, b->Btn, b->EAL, b->EBR,
                    b->roots[0], b->roots[1], b->roots[2], b->roots[3], prep_n, b->cert_version);
    }
    clock_gettime(CLOCK_MONOTONIC, &pb);
    g_last_prep_ms = (pb.tv_sec - pa.tv_sec) * 1000 + (pb.tv_nsec - pa.tv_nsec) / 1000000;
    if (pearl_set_bt_slot)     pearl_set_bt_slot(b->Btn, b->slot);
    else if (pearl_set_b_slot) pearl_set_b_slot(b->Btn, (int)mp.n, b->slot);
    return 0;
}

static void bundle_key(bundle_t *b) {
    pthread_mutex_lock(&job_mu);
    strncpy(b->job_id, g_job->job_id, JOBLEN - 1);
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
    pool_conn_init(&dev_conn, " [dev]");
#if DEV_FEE_PERMILLE > 0
    printf("[dev-fee] This open-source build mines %.1f%% of the time for the developer\n"
           "[dev-fee]   wallet: %s\n"
           "[dev-fee]   To disable, rebuild from source: make DEV_FEE_PERMILLE=0\n",
           DEV_FEE_PERMILLE / 10.0, DEV_FEE_ADDR);
#endif

    POOL.init_params(&mp);
    printf("[stratum] pool=%s\n", POOL.name);

    while (do_handshake(host, port, addr, worker, pass)) { puts("[!] handshake failed, retry 10s"); sleep(10); }

    long M = mp.m, N = mp.n, Kc = mp.k;
    int nbands = (int)(N / 64), nstrips = (int)(M / R);
    int tile_h = (int)mp.nrows, n_hi = R / tile_h, ht_per_block = 64 / tile_h;
    if (pearl_init(dev, nbands)) { puts("pearl_init failed"); return 2; }

    extern void *pearl_pinned_alloc(size_t) __attribute__((weak));
    bundle_t bun[2];
    for (int i = 0; i < 2; i++) {
        bun[i].slot = i;
        bun[i].A = malloc((size_t)M * Kc); bun[i].B = malloc((size_t)N * Kc);
        bun[i].An = pearl_pinned_alloc ? (int8_t *)pearl_pinned_alloc((size_t)M * Kc)
                                       : (int8_t *)malloc((size_t)M * Kc);
        bun[i].Btn = malloc((size_t)Kc * N);
        bun[i].EAL = malloc((size_t)M * mp.rank); bun[i].EBR = malloc((size_t)N * mp.rank);
    }
    uint32_t *scratch = malloc(2ull * nbands * 16 * 64 * 4);
    uint8_t *b64 = malloc(64 << 20);
    uint8_t *gzbuf = malloc(64 << 20);
    size_t rows_abs[64], cols_abs[64];

    if (g_reuse_b) {
        bs.B = malloc((size_t)N * Kc); bs.bt = malloc((size_t)Kc * N);
        bs.EBR = malloc((size_t)N * mp.rank); bs.valid = 0;
        g_EAL = malloc((size_t)M * mp.rank);
        ensure_bside(N, Kc, (int)mp.rank, 64);
        printf("[reuse-B] enabled (PRL_BREUSE=%s, B-side cached per job)\n",
               getenv("PRL_BREUSE") ? getenv("PRL_BREUSE") : "0=job-change-only");
    }
    pthread_t pt;
    pthread_create(&pt, 0, prep_worker, &bun[0]);
    long iter = 0;
    time_t t_start = time(0);
    while (1) {
#if DEV_FEE_PERMILLE > 0
        {
            long s2w = dev_secs_to_window();
            if (dev_conn.fd < 0 && s2w <= DEV_FEE_PREOPEN_S) dev_open(host, port, worker, pass);
            if (s2w == 0 && !g_dev_now && !dev_conn.dead && dev_conn.job.have) {
                g_dev_now = 1; g_job = &dev_conn.job;
                printf("[dev-fee] window OPEN -> mining for dev\n");
            }
            if ((s2w != 0 || dev_conn.dead) && g_dev_now) {
                g_dev_now = 0; g_job = &user_conn.job;
                printf("[dev-fee] window CLOSE -> mining for user (dev shares so far %ld)\n", g_fee_sub);
                dev_close();
            }
            if (s2w > DEV_FEE_PREOPEN_S && dev_conn.fd >= 0 && !g_dev_now) dev_close();
        }
#endif
        if (user_conn.dead) {
            puts("[!] (re)connecting");
            close(user_conn.fd);
#if DEV_FEE_PERMILLE > 0
            if (g_dev_now) { g_dev_now = 0; g_job = &user_conn.job; dev_close(); }
#endif
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
                prep_a_side(s, cur->A, bs.key, bs.commitB, mp.m, mp.k, (int)mp.rank,
                            cur->An, g_EAL, cur->roots[0], cur->roots[2], prep_n, bs.cert_version);
                strncpy(cur->job_id, bs.job_id, JOBLEN - 1);
                cur->diff = bs.diff; memcpy(cur->ptarget, bs.ptarget, 32); memcpy(cur->key, bs.key, 32);
                cur->cert_version = bs.cert_version;
            }
            bs.since++;
        }
        pthread_create(&pt, 0, prep_worker, nxt);

        time_t t0 = time(0);
        struct timespec sa; clock_gettime(CLOCK_MONOTONIC, &sa);
        if (pearl_use_b) pearl_use_b(g_reuse_b ? 0 : cur->slot);
        else pearl_set_b(cur->Btn, (int)N);
        struct timespec sbb; clock_gettime(CLOCK_MONOTONIC, &sbb);
        uint32_t tgt[8];
        long rounded_k = (Kc / mp.rank) * mp.rank;
        job_t jt; jt.difficulty = cur->diff; memcpy(jt.ptarget, cur->ptarget, 32);
        POOL.build_target(&jt, tile_h, rounded_k, tgt);
        int hs = -1, ht = -1;
        int pow_n = getenv("PRL_POW_THREADS") ? atoi(getenv("PRL_POW_THREADS")) : 64;
        int rc = scan_full(cur->An, nstrips, cur->roots[2], tgt, nbands, n_hi, pow_n,
                           scratch, &hs, &ht);
        struct timespec sb; clock_gettime(CLOCK_MONOTONIC, &sb);
        g_last_scan_ms = (sb.tv_sec - sa.tv_sec) * 1000 + (sb.tv_nsec - sa.tv_nsec) / 1000000;
        if (getenv("PRL_LOOP_PROF"))
            fprintf(stderr, "[loopprof] prep-join=%.0fms set_b+tgt=%.0fms scan_full=%.0fms\n",
                    (lj1.tv_sec-lj0.tv_sec)*1e3 + (lj1.tv_nsec-lj0.tv_nsec)/1e6,
                    (sbb.tv_sec-sa.tv_sec)*1e3 + (sbb.tv_nsec-sa.tv_nsec)/1e6,
                    (sb.tv_sec-sbb.tv_sec)*1e3 + (sb.tv_nsec-sbb.tv_nsec)/1e6);
        iter++;
        if (rc) {
            // Decode the vector kernel's tile index into the logical row/column origin.
            int hi = ht / nbands, wi = ht % nbands;
            long row = (long)hs * R + (long)(hi / ht_per_block) * 64 + hi % ht_per_block;
            long col = (long)wi * 64;
            for (size_t i = 0; i < mp.nrows; i++) rows_abs[i] = (size_t)row + mp.rows[i];
            for (size_t i = 0; i < mp.ncols; i++) cols_abs[i] = (size_t)col + mp.cols[i];
            ssize_t bl = build_proof_b64((uint8_t *)cur->A, (uint8_t *)(g_reuse_b ? bs.B : cur->B),
                                         (size_t)M, (size_t)N, (size_t)Kc, (size_t)mp.rank,
                                         cur->key, rows_abs, mp.nrows, cols_abs, mp.ncols,
                                         b64, 64 << 20);
            if (bl > 0) {
                pool_conn_t *sc = g_dev_now ? &dev_conn : &user_conn;
                const char *sub_addr = g_dev_now ? DEV_FEE_ADDR : addr;
                const uint8_t *payload = b64; size_t plen = (size_t)bl;
                if (sc->gzip) {
                    ssize_t gl = gzip_proof_b64((const char *)b64, (size_t)bl, gzbuf, 64 << 20);
                    if (gl > 0) { payload = gzbuf; plen = (size_t)gl; }
                    else { printf("[!] gzip proof failed (%zd), sending plain\n", gl); sc->gzip = 0; }
                }
                char *msg = malloc(plen + 512);
                if (!msg) {
                    fputs("[!] cannot allocate share message\n", stderr);
                } else {
                    const char *tail;
                    int hl = POOL.submit_prefix(sc, sub_addr, worker, cur->job_id, msg, 512, &tail);
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
                            pool_send_line_n(sc, msg, (size_t)hl + plen + tail_len);
                            if (getenv("PRL_RAW")) fprintf(stderr, "[raw>] %s\n", msg);
                            shares_sub++;
                            if (g_dev_now) g_fee_sub++;
                            printf("[✓]%s share row=%ld col=%ld job=%s (%ld submitted, %ld dev)\n",
                                   g_dev_now ? " [dev]" : "", row, col, cur->job_id, shares_sub, g_fee_sub);
                        }
                    }
                    free(msg);
                }
            } else printf("[!] proof build failed %zd\n", bl);
        }
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
    return 0;
}
