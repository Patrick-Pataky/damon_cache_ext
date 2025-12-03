#pragma once

#include <stdbool.h>
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
bool bit_vector_get(struct bit_vector *vect, size_t bit_idx);
void bit_vector_set(struct bit_vector *vect, size_t bit_idx, bool value);

struct bloom* bloom_init(size_t num_bits);
void bloom_free(struct bloom **b);

/**
 * Adds an address addr to the bloom filter b.
 */
void bloom_add(struct bloom *b, uint64_t addr);

/**
 * Checks if an address addr is possibly in the bloom filter b.
 * Returns true if possibly present, false if *definitely* not present.
 */
bool bloom_contains(struct bloom *b, uint64_t addr);
