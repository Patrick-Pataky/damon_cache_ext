#include "tinylfu.h"
#include <string.h>

#define DOORKEEPER_SIZE 10240
#define CBF_SIZE 10240

struct tinylfu* tinylfu_init() {
    struct tinylfu *tfu = (struct tinylfu*) malloc(sizeof(struct tinylfu));
    if (!tfu) return NULL;

    tfu->doorkeeper = bloom_init(DOORKEEPER_SIZE);
    if (!tfu->doorkeeper) {
        free(tfu);
        return NULL;
    }

    tfu->cbf = counting_bloom_init(CBF_SIZE);
    if (!tfu->cbf) {
        bloom_free(&tfu->doorkeeper);
        free(tfu);
        return NULL;
    }

    return tfu;
}

void tinylfu_free(struct tinylfu **tfu) {
    if (tfu && *tfu) {
        bloom_free(&(*tfu)->doorkeeper);
        counting_bloom_free(&(*tfu)->cbf);

        free(*tfu);
        *tfu = NULL;
    }
}

void tinylfu_access(struct tinylfu *tfu, uint64_t addr) {
    if (!tfu) return;

    if (!bloom_contains(tfu->doorkeeper, addr)) {
        bloom_add(tfu->doorkeeper, addr);
    } else {
        if (counting_bloom_add(tfu->cbf, addr)) {
            /* Reset and clear the doorkeeper */
            counting_bloom_reset(tfu->cbf);

            if (tfu->doorkeeper && tfu->doorkeeper->vector) {
                bloom_clear(tfu->doorkeeper);
            }
        }
    }
}

uint64_t tinylfu_estimate(struct tinylfu *tfu, uint64_t addr) {
    if (!tfu) return 0;

    uint64_t estimate = counting_bloom_estimate(tfu->cbf, addr);

    if (!bloom_contains(tfu->doorkeeper, addr)) {
        return estimate;
    }

    return estimate + 1;
}

bool tinylfu_admit(struct tinylfu *tfu, uint64_t new,
                   uint64_t victim_candidate) {
    if (!tfu) return true;

    uint64_t new_estimate    = tinylfu_estimate(tfu, new);
    uint64_t victim_estimate = tinylfu_estimate(tfu, victim_candidate);

    return new_estimate > victim_estimate;
}
