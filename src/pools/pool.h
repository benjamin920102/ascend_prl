/*
 * Pool frontend interface — separates the protocol layer (src/pools/) from the mining
 * engine (src/miner.c). Each binary links exactly one frontend providing the `POOL` symbol.
 * Shared stratum plumbing lives in stratum.c.
 */
#ifndef PEARL_POOL_H
#define PEARL_POOL_H
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#define LINE   8192
#define JOBLEN 64
#define HDRLEN 4096

/* a mining job (one per connection), filled by the frontend's dispatch from mining.notify */
typedef struct {
    char job_id[JOBLEN];
    uint8_t header[HDRLEN]; size_t header_len;
    double difficulty;
    uint8_t ptarget[32];
    int have_target;
    long height;
    int cert_version;   /* 1/2 = legacy (unsalted), 3+ = salted; defaults to 1 for pre-fork pools */
    int have;
} job_t;

/* mining params: miner-chosen (kryptex) or pool-dictated via pearl.set_mining_params (k1pool) */
typedef struct {
    long m, n, k, rank;
    size_t rows[64], cols[64]; size_t nrows, ncols;
    int have;
} mining_params_t;

/* one stratum connection; the engine runs two: user wallet and dev-fee wallet */
typedef struct {
    int fd;
    pthread_mutex_t send_mu;
    volatile int dead;
    int msg_id;
    job_t job;
    const char *tag;    /* "" for user, " [dev]" for dev-fee */
    int gzip;           /* 1 = pool negotiated type:"v2" -> send gzip(proof) (kryptex) */
} pool_conn_t;

/* the protocol-specific surface; exactly one instance (POOL) is linked per binary */
typedef struct {
    const char *name;
    int miner_chosen_params;
    void (*init_params)(mining_params_t *mp);
    int  (*open)(pool_conn_t *conn, const char *host, int port,
                 const char *addr, const char *worker, const char *pass, mining_params_t *mp);
    void (*dispatch)(pool_conn_t *conn, const char *line, mining_params_t *mp);
    void (*build_target)(const job_t *J, int tile_h, long rounded_k, uint32_t out[8]);
    int  (*submit_prefix)(pool_conn_t *conn, const char *addr, const char *worker,
                          const char *job_id, char *msg, size_t cap, const char **tail);
} pool_frontend_t;

extern const pool_frontend_t POOL;

/* ---- shared stratum plumbing (stratum.c) ---- */
extern long shares_sub, shares_acc, shares_rej;
extern pthread_mutex_t job_mu;

void pool_conn_init(pool_conn_t *c, const char *tag);
void pool_send_line(pool_conn_t *c, const char *s);
int  pool_connect(pool_conn_t *c, const char *host, int port);
void pool_start_reader(pool_conn_t *c, mining_params_t *mp);
void pool_handle_result(pool_conn_t *c, const char *line);

/* tiny JSON helpers */
const char *jfind(const char *s, const char *key);
int    jstr(const char *s, const char *key, char *out, size_t cap);
double jnum(const char *s, const char *key, double dflt);
int    jarr_sz(const char *p, size_t *out, int cap);
int    hex2bin(const char *h, uint8_t *out, size_t cap);

/* target math */
void mul_limbs(const uint32_t q[8], uint64_t f, uint32_t out[8]);
void target_from_diff(double diff, long tile_elems_rounded_k, uint32_t out[8]);
void target_from_be(const uint8_t be[32], long tile_elems_rounded_k, uint32_t out[8]);

#endif /* PEARL_POOL_H */
