#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include "hash.h"
#include "utils.h"

#define NUM_HASH_FUNCTIONS 4
#define BITS_PER_COUNTER 4

struct counting_bloom {
    uint64_t *counters;
    size_t size;
    hash_fct hash_functions[NUM_HASH_FUNCTIONS];
};

struct counting_bloom* counting_bloom_init(size_t num_bits);
void counting_bloom_free(struct counting_bloom **cb);
void counting_bloom_add(struct counting_bloom *cb, const char *s, size_t len);
bool counting_bloom_contains(
    struct counting_bloom *cb, const char *s, size_t len
);
