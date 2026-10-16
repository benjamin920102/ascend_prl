/* Host-only regression: cc -std=c11 -Wall -Wextra -Werror tests/test_scan_strip.c -o /tmp/test_scan_strip && /tmp/test_scan_strip */
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#define K 4
#include "../src/scan_strip_async.c"
static int submitted, completed, hit_at, key_calls, nhi_calls;
static const int8_t *base;
void pearl_strip_submit_fast(const int8_t *a) {
    assert(a == base + (size_t)submitted * R * K);
    assert(submitted - completed < 2);
    submitted++;
}
void pearl_strip_wait_done(void) { assert(completed < submitted); completed++; }
void pearl_set_key_target(const uint32_t *key, const uint32_t *target) {
    assert(key[0] == 0 && target[0] == 0); key_calls++;
}
void pearl_set_nhi(int n_hi) { assert(n_hi == 8); nhi_calls++; }
int pearl_get_hit_result(int *hs, int *ht) {
    if (completed - 1 != hit_at) return 0;
    *hs = hit_at; *ht = 37; return 1;
}
int main(void) {
    int8_t a[7 * R * K] = {0};
    uint8_t key[32] = {0}; uint32_t target[8] = {0}; base = a;
    for (int n = 0; n <= 7; n++) {
        for (int h = -1; h < n; h++) {
            submitted = completed = key_calls = nhi_calls = 0; hit_at = h;
            int hs = -1, ht = -1;
            int rc = scan_full(a, n, key, target, 20, 8, 1, NULL, &hs, &ht);
            assert(rc == (h >= 0));
            assert(submitted == completed); /* safe next scan / B-buffer reset */
            if (h >= 0) { assert(hs == h && ht == 37); }
            else { assert(submitted == n && hs == -1 && ht == -1); }
            assert(key_calls == (n > 0) && nhi_calls == (n > 0));
        }
    }
    puts("PASS: empty/single/odd/even scans, all hit positions, pointer stride, drain");
}
