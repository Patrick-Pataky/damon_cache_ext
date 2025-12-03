#pragma once

#include <stdlib.h>
#include <stdint.h>

#define NUM_HASH_FUNCTIONS 4

struct hashes {
    uint32_t h[NUM_HASH_FUNCTIONS];
};

/**
 * Thomas Wang 64 bit Mix Functions
 * https://gist.github.com/badboy/6267743
 */
static __always_inline uint64_t hash_64(uint64_t key) {
    key = (~key) + (key << 21); // key = (key << 21) - key - 1;
    key = key ^ (key >> 24);
    key = (key + (key << 3)) + (key << 8); // key * 265
    key = key ^ (key >> 14);
    key = (key + (key << 2)) + (key << 4); // key * 21
    key = key ^ (key >> 28);

    return key;
}

static __always_inline void get_hashes(
    uint64_t key, struct hashes *out
) {
    uint64_t hash = hash_64(key);

    uint32_t h1 = (uint32_t) hash;
    uint32_t h2 = (uint32_t) (hash >> 32);

    // Formula: h_i = (h1 + i * h2)
    for (size_t i = 0; i < NUM_HASH_FUNCTIONS; i++) {
        out->h[i] = h1 + i * h2;
    }
}

