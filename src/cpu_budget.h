#ifndef PRL_CPU_BUDGET_H
#define PRL_CPU_BUDGET_H
/* Compute-team sizes, including the prep caller; control/I/O threads are excluded. */
int prl_cpu_total(void);
int prl_cpu_prep_threads(void);
int prl_cpu_proof_threads(void);
void prl_cpu_enter(void);
void prl_cpu_leave(void);
void prl_b3_shutdown(void);
#endif
