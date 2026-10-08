/* DCMI detects NPU tenants that cannot be reliably seen through /dev/davinci*
 * file watches. A non-miner PID (including a foreign-namespace PID) causes the
 * miner to pause via SIGUSR1; SIGUSR2 resumes it after the device is clear.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <regex.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "dcmi_interface_api.h"

#define MAXDEV  16
#define MAXPROC 256
#define MAXMINE 16

static volatile sig_atomic_t g_ack = 0;
static void on_ack(int s) { (void)s; g_ack = 1; }

static const char *g_notify = 0;
static int g_ack_timeout_ms = 8000;
static regex_t g_minere;

struct managed { int logic, card, device, paused; };

static void notify(const char *state, struct managed *m) {
    if (!g_notify) return;
    char cmd[600];
    snprintf(cmd, sizeof cmd, "%s %s %d", g_notify, state, m->logic);
    int rc = system(cmd); (void)rc;
}

static int is_miner(int pid) {
    if (pid <= 0) return 0;
    char p[64], comm[64] = "";
    snprintf(p, sizeof p, "/proc/%d/comm", pid);
    FILE *f = fopen(p, "r");
    if (!f) return 0;
    if (fgets(comm, sizeof comm, f)) comm[strcspn(comm, "\n")] = 0;
    fclose(f);
    return regexec(&g_minere, comm, 0, 0, 0) == 0;
}

// PID 0 or an inaccessible /proc entry is conservatively treated as foreign.
static int scan_device(struct managed *m, int *mp, int cap, int *nminer) {
    struct dcmi_proc_mem_info procs[MAXPROC];
    int n = MAXPROC;
    if (dcmi_get_device_resource_info(m->card, m->device, procs, &n) != 0) return -1;
    int foreign = 0; *nminer = 0;
    for (int i = 0; i < n; i++) {
        if (is_miner(procs[i].proc_id)) { if (*nminer < cap) mp[(*nminer)++] = procs[i].proc_id; }
        else foreign++;
    }
    return foreign;
}

// Wait for the miner's quiescence ACK rather than assuming SIGUSR1 is immediate.
static void pause_dev(struct managed *m, int *mp, int nminer) {
    if (m->paused) return;
    g_ack = 0;
    for (int i = 0; i < nminer; i++)
        if (kill(mp[i], SIGUSR1)) fprintf(stderr, "[guard] dev%d signal %d: %s\n", m->logic, mp[i], strerror(errno));
    int waited = 0; struct timespec ts = { 0, 20L * 1000 * 1000 };
    while (!g_ack && waited < g_ack_timeout_ms) { nanosleep(&ts, 0); waited += 20; }
    printf("[guard] dev%d PAUSE %d miner(s) (%s, %dms)\n",
           m->logic, nminer, g_ack ? "ACK" : "no-ack/timeout", waited);
    m->paused = 1; notify("pause", m);
}

static void resume_dev(struct managed *m, int *mp, int nminer) {
    if (!m->paused) return;
    for (int i = 0; i < nminer; i++) kill(mp[i], SIGUSR2);
    printf("[guard] dev%d RESUME %d miner(s)\n", m->logic, nminer);
    m->paused = 0; notify("resume", m);
}

int main(int argc, char **argv) {
    setvbuf(stdout, 0, _IOLBF, 0);
    int poll_ms = 500;
    const char *minre = "ascend_prl";
    struct managed mg[MAXDEV]; int nmg = 0;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-p") && i + 1 < argc) poll_ms = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-t") && i + 1 < argc) g_ack_timeout_ms = atoi(argv[++i]) * 1000;
        else if (!strcmp(argv[i], "-m") && i + 1 < argc) minre = argv[++i];
        else if (!strcmp(argv[i], "-n") && i + 1 < argc) g_notify = argv[++i];
        else {
            if (nmg >= MAXDEV) { fprintf(stderr, "[guard] too many devices\n"); return 1; }
            mg[nmg].logic = atoi(argv[i]); mg[nmg].paused = 0; nmg++;
        }
    }
    if (nmg == 0) {
        fprintf(stderr, "usage: %s [-p poll_ms] [-t ack_s] [-m miner_regex] [-n notify_cmd] <dev>...\n"
                        "  Poll DCMI per device; pause the miner (SIGUSR1) when a foreign tenant appears,\n"
                        "  resume (SIGUSR2) when the die is the miner's alone again.\n", argv[0]);
        return 1;
    }
    if (regcomp(&g_minere, minre, REG_EXTENDED | REG_NOSUB)) { fprintf(stderr, "[guard] bad -m regex\n"); return 1; }
    if (dcmi_init() != 0) { fprintf(stderr, "[guard] dcmi_init failed (need driver access)\n"); return 2; }
    for (int i = 0; i < nmg; i++) {
        if (dcmi_get_card_id_device_id_from_logicid(&mg[i].card, &mg[i].device, (unsigned)mg[i].logic) != 0) {
            fprintf(stderr, "[guard] davinci%d -> card/device map failed\n", mg[i].logic); return 2;
        }
        printf("[guard] managing davinci%d (card %d dev %d)\n", mg[i].logic, mg[i].card, mg[i].device);
    }
    struct sigaction sa; memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_ack; sigemptyset(&sa.sa_mask);
    sigaction(SIGUSR1, &sa, 0);
    signal(SIGPIPE, SIG_IGN);
    printf("[guard] poll %dms, ack timeout %ds, miner=/%s/, %d device(s)\n",
           poll_ms, g_ack_timeout_ms / 1000, minre, nmg);

    struct timespec pt = { poll_ms / 1000, (long)(poll_ms % 1000) * 1000000 };
    for (;;) {
        for (int i = 0; i < nmg; i++) {
            int mp[MAXMINE], nminer = 0;
            int f = scan_device(&mg[i], mp, MAXMINE, &nminer);
            if (f < 0) continue;
            if (f > 0 && nminer > 0) pause_dev(&mg[i], mp, nminer);
            else if (f == 0) resume_dev(&mg[i], mp, nminer);
        }
        nanosleep(&pt, 0);
    }
    return 0;
}
