#include "bloom.h"

struct bit_vector* bit_vector_init(size_t num_bits) {
    struct bit_vector *res = (struct bit_vector*) malloc(
        sizeof(struct bit_vector)
    );

    if (res) {
        res->size = num_bits;
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

void bit_vector_free(struct bit_vector **vect) {
    if (vect && *vect) {
        free((*vect)->start);
        free(*vect);
        *vect = NULL;
    }
}

bool bit_vector_get(struct bit_vector *vect, size_t bit_idx) {
    if (!vect || bit_idx >= vect->size) {
        return false;
    }

    size_t word_idx   = bit_idx / NUM_BITS(uint64_t);
    size_t bit_offset = bit_idx % NUM_BITS(uint64_t);

    return (vect->start[word_idx] >> bit_offset) & 1;
}

void bit_vector_set(struct bit_vector *vect, size_t bit_idx, bool value) {
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

struct bloom* bloom_init(size_t num_bits) {
    struct bloom *b = (struct bloom*) malloc(sizeof(struct bloom));

    if (b) {
        b->vector = bit_vector_init(num_bits);

        if (!b->vector) {
            free(b);
            return NULL;
        }

        b->hash_functions[0] = djb33_hash;
        b->hash_functions[1] = fnv32_hash;
        b->hash_functions[2] = ejb_hash;
        b->hash_functions[3] = oat_hash;
    }

    return b;
}

void bloom_free(struct bloom **b) {
    if (b && *b) {
        bit_vector_free(&(*b)->vector);
        free(*b);
        *b = NULL;
    }
}

void bloom_add(struct bloom *b, const char *s, size_t len) {
    if (!b) return;

    for (size_t i = 0; i < NUM_HASH_FUNCTIONS; i++) {
        uint32_t hash = b->hash_functions[i](s, len);
        bit_vector_set(b->vector, hash % b->vector->size, true);
    }
}

bool bloom_check(struct bloom *b, const char *s, size_t len) {
    if (!b) return false;

    for (int i = 0; i < NUM_HASH_FUNCTIONS; i++) {
        uint32_t hash = b->hash_functions[i](s, len);
        if (!bit_vector_get(b->vector, hash % b->vector->size)) {
            return false;
        }
    }
    return true;
}
