#include "bloom.h"

struct bit_vector* bit_vector_init(size_t num_bits)
{
    struct bit_vector *res = (struct bit_vector*) malloc(
        sizeof(struct bit_vector)
    );

    if (res) {
        res->size = num_bits;

        // Round up to nearest uint64_t
        size_t num_words = (num_bits + NUM_BITS(uint64_t) - 1)
                                / NUM_BITS(uint64_t);

        res->start = (uint64_t*) calloc(num_words, sizeof(uint64_t));

        if (!res->start) {
            free(res);
            return NULL;
        }
    }

    return res;
}

void bit_vector_free(struct bit_vector **vect)
{
    if (vect && *vect) {
        free((*vect)->start);
        free(*vect);
        *vect = NULL;
    }
}

struct bloom* bloom_init(size_t num_bits)
{
    struct bloom *b = (struct bloom*) malloc(sizeof(struct bloom));

    if (b) {
        b->vector = bit_vector_init(num_bits);

        if (!b->vector) {
            free(b);
            return NULL;
        }
    }

    return b;
}

void bloom_free(struct bloom **b)
{
    if (b && *b) {
        bit_vector_free(&(*b)->vector);
        free(*b);
        *b = NULL;
    }
}

void bloom_add_with_hashes(struct bloom *b, struct hashes *hs)
{
    if (!b || !hs) return;

    for (size_t i = 0; i < NUM_HASH_FUNCTIONS; i++) {
        uint32_t hash = hs->h[i];
        bit_vector_set(b->vector, hash % b->vector->size, true);
    }
}

void bloom_add(struct bloom *b, uint64_t addr)
{
    if (!b) return;

    struct hashes hs;
    get_hashes(addr, &hs);
    bloom_add_with_hashes(b, &hs);
}

void bloom_clear(struct bloom *b)
{
    if (!b) return;

    size_t num_words = (b->vector->size + NUM_BITS(uint64_t) - 1)
                            / NUM_BITS(uint64_t);
    memset(b->vector->start, 0, num_words * sizeof(uint64_t));
}

bool bloom_contains_with_hashes(struct bloom *b, struct hashes *hs)
{
    if (!b || !hs) return false;

    for (size_t i = 0; i < NUM_HASH_FUNCTIONS; i++) {
        uint32_t hash = hs->h[i];
        if (!bit_vector_get(b->vector, hash % b->vector->size)) {
            return false;
        }
    }
    return true;
}

bool bloom_contains(struct bloom *b, uint64_t addr)
{
    if (!b) return false;

    struct hashes hs;
    get_hashes(addr, &hs);
    return bloom_contains_with_hashes(b, &hs);
}
