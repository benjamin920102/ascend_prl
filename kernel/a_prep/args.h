#pragma once
#include <stdint.h>
struct PearlPrepArgs {
 uint64_t seed,m,k;
 uint32_t rank,cert,random_fill,threads;
 uint8_t key[32],commit_b[32];
 int8_t *a,*eal;
 uint16_t *first,*second;
 uint8_t *roots; // rootA || commitA
};
