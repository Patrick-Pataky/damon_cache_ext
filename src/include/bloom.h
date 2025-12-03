#pragma once

#include <stdbool.h>
#include <string.h>
#include "hash.h"
#include "utils.h"

#define NUM_HASH_FUNCTIONS 4

struct bit_vector {
    uint64_t* start;
    size_t size;
};

struct bloom {
    struct bit_vector *vector;
};

struct bit_vector* bit_vector_init(size_t num_bits);
void bit_vector_free(struct bit_vector **vect);

static inline bool bit_vector_get(struct bit_vector *vect, size_t bit_idx)
{
    if (!vect || bit_idx >= vect->size) {
        return false;
    }

    size_t word_idx   = bit_idx / NUM_BITS(uint64_t);
    size_t bit_offset = bit_idx % NUM_BITS(uint64_t);

    return (vect->start[word_idx] >> bit_offset) & 1;
}

static inline void bit_vector_set(struct bit_vector *vect, size_t bit_idx, bool value)
{
    if (!vect || bit_idx >= vect->size) {
        return;
    }

    size_t word_idx   = bit_idx / NUM_BITS(uint64_t);
    size_t bit_offset = bit_idx % NUM_BITS(uint64_t);

    if (value) {
        vect->start[word_idx] |= (1ULL << bit_offset);
    } else {
        vect->start[word_idx] &= ~(1ULL << bit_offset);
    }
}

struct bloom* bloom_init(size_t num_bits);
void bloom_free(struct bloom **b);

/**
 * Adds an address addr to the bloom filter b.
 */
void bloom_add(struct bloom *b, uint64_t addr);
void bloom_add_with_hashes(struct bloom *b, struct hashes *hs);

/**
 * Clears all entries in the bloom filter b.
 */
void bloom_clear(struct bloom *b);

/**
 * Checks if an address addr is possibly in the bloom filter b.
 * Returns true if possibly present, false if *definitely* not present.
 */
bool bloom_contains(struct bloom *b, uint64_t addr);
bool bloom_contains_with_hashes(struct bloom *b, struct hashes *hs);
