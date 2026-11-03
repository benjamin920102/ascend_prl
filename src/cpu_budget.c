#define _GNU_SOURCE
#include "cpu_budget.h"
#include <pthread.h>
#include <sched.h>
#include <stdlib.h>
#include <unistd.h>

static pthread_once_t once = PTHREAD_ONCE_INIT;
static pthread_mutex_t serial_mu = PTHREAD_MUTEX_INITIALIZER;
static int total, prep, proof;
static int env_count(const char *name, int fallback, int cap) {
    const char *s = getenv(name);
    char *end;
    long n = s ? strtol(s, &end, 10) : 0;
    if (!s || end == s || *end || n < 1) return fallback;
    return n > cap ? cap : (int)n;
}
static void init_budget(void) {
    cpu_set_t affinity;
    long n = sysconf(_SC_NPROCESSORS_ONLN);
    int available = n > 0 ? (int)n : 1;
    if (!sched_getaffinity(0, sizeof affinity, &affinity)) {
        int count = CPU_COUNT(&affinity);
        if (count > 0) available = count;
    }
    total = env_count("PRL_CPU_THREADS", available, available);
    if (total == 1) { prep = proof = 1; return; }
    prep = env_count("PRL_PREP_THREADS", total - (total / 4 ? total / 4 : 1), total - 1);
    /* One partition for prep/OpenMP/BLAKE3, the other for proof/Rayon. */
    proof = env_count("PRL_PROOF_THREADS", total - prep, total - prep);
}
int prl_cpu_total(void) { pthread_once(&once, init_budget); return total; }
int prl_cpu_prep_threads(void) { pthread_once(&once, init_budget); return prep; }
int prl_cpu_proof_threads(void) { pthread_once(&once, init_budget); return proof; }
/* A one-CPU process serializes CPU preparation and proof+encoding. */
void prl_cpu_enter(void) { if (prl_cpu_total() == 1) pthread_mutex_lock(&serial_mu); }
void prl_cpu_leave(void) { if (prl_cpu_total() == 1) pthread_mutex_unlock(&serial_mu); }
