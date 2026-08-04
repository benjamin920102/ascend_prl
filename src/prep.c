/*
 * CANN / Ascend NPU Compatible prep.c
 * - Optimized for ARM NEON / AVX SIMD
 * - 64-byte Aligned Memory Allocation for CANN/ACL DMA compatibility
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* =====================================================
   SIMD Detection and Capability Flags
   ===================================================== */

#if defined(__AVX512F__) && defined(__AVX512BW__)
    #define SIMD_AVX512
    #define SIMD_LEVEL 512
    #include <immintrin.h>
#elif defined(__AVX2__)
    #define SIMD_AVX2
    #define SIMD_LEVEL 256
    #include <immintrin.h>
#elif defined(__ARM_NEON__)
    #define SIMD_NEON
    #define SIMD_LEVEL 128
    #include <arm_neon.h>
#else
    #define SIMD_SCALAR
    #define SIMD_LEVEL 0
#endif

/* =====================================================
   SIMD Accelerators (u2i_worker)
   ===================================================== */

#ifdef SIMD_AVX512
static void u2i_worker_avx512(const uint8_t *raw, int8_t *out, int64_t n) {
    __m512i mask_vec = _mm512_set1_epi8(0x3F);
    __m512i offset_vec = _mm512_set1_epi8(32);
    int64_t i = 0;
    for (; i + 63 < n; i += 64) {
        __m512i raw_vec = _mm512_loadu_si512((__m512i *)(raw + i));
        __m512i masked = _mm512_and_si512(raw_vec, mask_vec);
        __m512i result = _mm512_sub_epi8(masked, offset_vec);
        _mm512_storeu_si512((__m512i *)(out + i), result);
    }
    for (; i < n; i++) {
        out[i] = (int8_t)((raw[i] & 0x3F) - 32);
    }
}
#endif

#ifdef SIMD_AVX2
static void u2i_worker_avx2(const uint8_t *raw, int8_t *out, int64_t n) {
    __m256i mask_vec = _mm256_set1_epi8(0x3F);
    __m256i offset_vec = _mm256_set1_epi8(32);
    int64_t i = 0;
    for (; i + 31 < n; i += 32) {
        __m256i raw_vec = _mm256_loadu_si256((__m256i *)(raw + i));
        __m256i masked = _mm256_and_si256(raw_vec, mask_vec);
        __m256i result = _mm256_sub_epi8(masked, offset_vec);
        _mm256_storeu_si256((__m256i *)(out + i), result);
    }
    for (; i < n; i++) {
        out[i] = (int8_t)((raw[i] & 0x3F) - 32);
    }
}
#endif

#ifdef SIMD_NEON
static void u2i_worker_neon(const uint8_t *raw, int8_t *out, int64_t n) {
    uint8x16_t mask_vec = vdupq_n_u8(0x3F);
    int8x16_t offset_vec = vdupq_n_s8(32);
    int64_t i = 0;
    for (; i + 15 < n; i += 16) {
        uint8x16_t raw_vec = vld1q_u8(raw + i);
        uint8x16_t masked = vandq_u8(raw_vec, mask_vec);
        int8x16_t masked_s8 = vreinterpretq_s8_u8(masked);
        int8x16_t result = vsubq_s8(masked_s8, offset_vec);
        vst1q_s8(out + i, result);
    }
    for (; i < n; i++) {
        out[i] = (int8_t)((raw[i] & 0x3F) - 32);
    }
}
#endif

static void u2i_worker_scalar(const uint8_t *raw, int8_t *out, int64_t n) {
    for (int64_t i = 0; i < n; i++) {
        out[i] = (int8_t)((raw[i] & 0x3F) - 32);
    }
}

static inline void prep_random_simd(const uint8_t *raw, int8_t *out, int64_t n) {
#ifdef SIMD_AVX512
    u2i_worker_avx512(raw, out, n);
#elif defined(SIMD_AVX2)
    u2i_worker_avx2(raw, out, n);
#elif defined(SIMD_NEON)
    u2i_worker_neon(raw, out, n);
#else
    u2i_worker_scalar(raw, out, n);
#endif
}

/* =====================================================
   High-Level APIs (Required by miner.c)
   ===================================================== */

void prep_random(const uint8_t *raw, int8_t *out, int64_t n) {
    prep_random_simd(raw, out, n);
}

void prep_a_side(
    const int8_t *A, const int8_t *EAL, int8_t *out,
    const uint16_t *f, const uint16_t *s,
    int64_t m, int64_t k, int R) {
    for (int64_t r = 0; r < m; r++) {
        const int8_t *ar = A + r * k;
        const int8_t *el = EAL + r * R;
        int8_t *o = out + r * k;
        for (int64_t j = 0; j < k; j++) {
            o[j] = (int8_t)(ar[j] + el[f[j]] - el[s[j]]);
        }
    }
}

void prep_b_side(
    const int8_t *B, const int8_t *EBR, int8_t *bt,
    const uint16_t *f, const uint16_t *s,
    int64_t k, int64_t n, int R) {
    
    int64_t nbands = n / 64;
    int64_t NFOLD = k / R;

    for (int64_t jp = 0; jp < nbands; jp++) {
        for (int64_t p = 0; p < NFOLD; p++) {
            for (int64_t m = 0; m < 64; m++) {
                int64_t col = jp * 64 + m;
                const int8_t *bcol = B + col * k;
                const int8_t *ecol = EBR + col * R;
                int8_t *dst = bt + ((jp * NFOLD + p) * 64 + m) * R;

                for (int64_t ki = 0; ki < R; ki++) {
                    int64_t row = p * R + ki;
                    dst[ki] = (int8_t)(bcol[row] + ecol[f[row]] - ecol[s[row]]);
                }
            }
        }
    }
}

void prep_random_bt(
    const uint8_t *raw_b, const int8_t *EBR, int8_t *bt,
    const uint16_t *f, const uint16_t *s,
    int64_t k, int64_t n, int R) {
    
    int64_t total = k * n;
    int8_t *b_conv = NULL;

    // Use 64-byte alignment mandatory for CANN / Ascend NPU DMA Engine
    if (posix_memalign((void **)&b_conv, 64, total) != 0 || !b_conv) {
        return;
    }

    // Step 1: SIMD conversion
    prep_random_simd(raw_b, b_conv, total);

    // Step 2: B-side pack
    prep_b_side(b_conv, EBR, bt, f, s, k, n, R);

    free(b_conv);
}

const char* simd_level_string(void) {
#ifdef SIMD_AVX512
    return "AVX-512";
#elif defined(SIMD_AVX2)
    return "AVX2";
#elif defined(SIMD_NEON)
    return "NEON";
#else
    return "Scalar";
#endif
}

int simd_width_bits(void) {
    return SIMD_LEVEL;
}
