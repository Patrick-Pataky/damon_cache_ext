#pragma once

#include <stdlib.h>
#include <stdint.h>

typedef uint32_t (*hash_fct)(const char* s, size_t len);

/**
 * Note: the following hash functions are taken from:
 *       https://gist.github.com/sgsfak/9ba382a0049f6ee885f68621ae86079b
 */

/*
 * The Dan Bernstein popuralized hash..  See
 * https://github.com/pjps/ndjbdns/blob/master/cdb_hash.c#L26 Due to hash
 * collisions it seems to be replaced with "siphash" in n-djbdns, see
 * https://github.com/pjps/ndjbdns/commit/16cb625eccbd68045737729792f09b4945a4b508
 */
uint32_t djb33_hash(const char* s, size_t len);

/*
 *
 * The Java hash, but really no-one seems to know where it came from, see
 * https://bugs.java.com/bugdatabase/view_bug.do?bug_id=4045622
 */
uint32_t h31_hash(const char* s, size_t len);

/*
 * The FNV Hash, or more precisely the "FNV-1a alternate algorithm"
 * See: http://www.isthe.com/chongo/tech/comp/fnv/
 *      https://en.wikipedia.org/wiki/Fowler–Noll–Vo_hash_function
 */
uint32_t fnv32_hash(const char *s, size_t len);

/*
 * "This came from ejb's hsearch."
 */
uint32_t ejb_hash(const char *s, size_t len);

/*
 * Bob Jenkins "One-at-a-time" hash
 */
uint32_t oat_hash(const char *s, size_t len);

extern hash_fct hash_functions[];
