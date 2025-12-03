#pragma once

#include "utils.h"
#include "bloom.h"
#include "counting_bloom.h"

struct tinylfu {
    struct bloom *doorkeeper;
    struct counting_bloom *cbf;
};

struct tinylfu* tinylfu_init();
void tinylfu_free(struct tinylfu **tfu);

/**
 * Records a page access. Must be called on every access.
 */
void tinylfu_access(struct tinylfu *tfu, uint64_t addr);

/**
 * Estimates the frequency of accesses to the given address addr.
 */
uint64_t tinylfu_estimate(struct tinylfu *tfu, uint64_t addr);

/**
 * Decides whether to admit a new page "new" over a victim candidate
 * "victim_candidate", chosen by the cache's eviction policy.
 *
 * Returns true if "new" should be admitted, false otherwise.
 */
bool tinylfu_admit(struct tinylfu *tfu, uint64_t new, uint64_t victim_candidate);
