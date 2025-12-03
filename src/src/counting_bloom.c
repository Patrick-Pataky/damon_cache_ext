#include "counting_bloom.h"

#define COUNTER_MASK ((1ULL << BITS_PER_COUNTER) - 1)

struct counting_bloom* counting_bloom_init(size_t num_counters)
{
    struct counting_bloom *cb = (struct counting_bloom*)
                                    malloc(sizeof(struct counting_bloom));

    if (cb) {
        cb->size = num_counters;
        size_t total_bits = num_counters * BITS_PER_COUNTER;
        size_t num_words  = (total_bits + NUM_BITS(uint64_t) - 1)
                                / NUM_BITS(uint64_t);
        cb->counters = (uint64_t*) calloc(num_words, sizeof(uint64_t));

        if (!cb->counters) {
            free(cb);
            return NULL;
        }

        cb->hash_functions[0] = djb33_hash;
        cb->hash_functions[1] = fnv32_hash;
        cb->hash_functions[2] = ejb_hash;
        cb->hash_functions[3] = oat_hash;
    }

    return cb;
}

void counting_bloom_free(struct counting_bloom **cb)
{
    if (cb && *cb) {
        free((*cb)->counters);
        free(*cb);
        *cb = NULL;
    }
}

static inline uint64_t get_counter(struct counting_bloom *cb, size_t idx) {
    size_t word_idx   = (idx * BITS_PER_COUNTER) / NUM_BITS(uint64_t);
    size_t bit_offset = (idx * BITS_PER_COUNTER) % NUM_BITS(uint64_t);

    return (cb->counters[word_idx] >> bit_offset) & COUNTER_MASK;
}

static inline void set_counter(struct counting_bloom *cb, size_t idx,
                               uint64_t val) {
    size_t word_idx   = (idx * BITS_PER_COUNTER) / NUM_BITS(uint64_t);
    size_t bit_offset = (idx * BITS_PER_COUNTER) % NUM_BITS(uint64_t);

    cb->counters[word_idx] &= ~(COUNTER_MASK << bit_offset);
    cb->counters[word_idx] |= (val & COUNTER_MASK) << bit_offset;
}

void counting_bloom_add(struct counting_bloom *cb, const char *s, size_t len)
{
    if (!cb) return;

    for (int i = 0; i < NUM_HASH_FUNCTIONS; i++) {
        uint32_t hash = cb->hash_functions[i](s, len);
        size_t idx = hash % cb->size;

        uint64_t val = get_counter(cb, idx);
        if (val < COUNTER_MASK) {
            set_counter(cb, idx, val + 1);
        }
    }
}

bool counting_bloom_contains(
    struct counting_bloom *cb, const char *s, size_t len
)
{
    if (!cb) return false;

    for (int i = 0; i < NUM_HASH_FUNCTIONS; i++) {
        uint32_t hash = cb->hash_functions[i](s, len);
        size_t idx = hash % cb->size;

        if (get_counter(cb, idx) == 0) {
            return false;
        }
    }

    return true;
}
