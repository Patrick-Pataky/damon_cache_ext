#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include "hash.h"
#include "utils.h"

#define BITS_PER_COUNTER 4

struct counting_bloom {
    uint64_t *counters;
    size_t size;
};

struct counting_bloom* counting_bloom_init(size_t num_bits);
void counting_bloom_free(struct counting_bloom **cb);

/**
 * Given an address addr, for each of the k hash functions h_i,
 * increments the minimal counter among all h_i(addr).
 */
void counting_bloom_add(struct counting_bloom *cb, uint64_t addr);

/**
 * Given an address addr, for each of the k hash functions h_i,
 * returns the minimum counter value among all h_i(addr).
 */
uint64_t counting_bloom_estimate(struct counting_bloom *cb, uint64_t addr);
