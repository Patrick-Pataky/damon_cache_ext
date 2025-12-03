#pragma once

#include <limits.h>

// C = cache size (in bytes) = 2^CACHE_SIZE_BITS
#define CACHE_SIZE_BITS (30) // 1 GiB

// W = sample size (in bytes) = 2^SAMPLE_SIZE_BITS
// Must be much larger than CACHE_SIZE_BITS
// Number of requests that are tracked before the reset().
#define SAMPLE_SIZE_BITS (10 * CACHE_SIZE_BITS)

// Number of bits used for each counter in the counting bloom filter
// In the paper, each counter can count up to W / C.
#define BITS_PER_COUNTER (SAMPLE_SIZE_BITS - CACHE_SIZE_BITS)

#define NUM_HASH_FUNCTIONS 4

#define NUM_BITS(type) (sizeof(type) * CHAR_BIT)
