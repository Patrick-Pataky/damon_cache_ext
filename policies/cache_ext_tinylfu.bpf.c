#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "cache_ext_lib.bpf.h"
#include "dir_watcher.bpf.h"

char _license[] SEC("license") = "GPL";

// #define DEBUG
#ifdef DEBUG
    #define dbg_printk(fmt, ...) bpf_printk(fmt, ##__VA_ARGS__)
#else
    #define dbg_printk(fmt, ...)
#endif

// Constants
#define CHAR_BIT 8
#define PAGE_SHIFT 12
#define NUM_BITS(type) (sizeof(type) * CHAR_BIT)
#define DOORKEEPER_SIZE 262144
#define CBF_SIZE 262144
#define NUM_HASH_FUNCTIONS 4
#define BITS_PER_COUNTER 4      // Must be a power of 2
#define COUNTER_MASK ((1 << BITS_PER_COUNTER) - 1)

// 1GiB (= 2^30/2^12)
#define CACHE_SIZE_BITS 18
// 8GiB (= 2^33/2^12)
// #define CACHE_SIZE_BITS 21

#define SAMPLE_SIZE_BITS (BITS_PER_COUNTER + CACHE_SIZE_BITS)

static u64 global_counter = 0;

// Maps
// Array sizes
#define DOORKEEPER_MAP_SIZE (DOORKEEPER_SIZE / NUM_BITS(u64) + 1)
#define CBF_MAP_SIZE (CBF_SIZE / (NUM_BITS(u64) / BITS_PER_COUNTER) + 1)

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, DOORKEEPER_MAP_SIZE);
    __type(key, u32);
    __type(value, u64);
} doorkeeper_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, CBF_MAP_SIZE);
    __type(key, u32);
    __type(value, u64);
} cbf_map SEC(".maps");

// Hash function (Thomas Wang 64 bit Mix Function)
static __always_inline u64 hash_64(u64 key) {
    key = (~key) + (key << 21);
    key = key ^ (key >> 24);
    key = (key + (key << 3)) + (key << 8);
    key = key ^ (key >> 14);
    key = (key + (key << 2)) + (key << 4);
    key = key ^ (key >> 28);
    return key;
}

static __always_inline u64 get_folio_id(u64 ino, u64 index) {
    // Simple bitwise mixing to avoid the overhead of multiple expensive hash calls.
    // This technique (XOR with a rotated value) is a standard hash combination primitive,
    // often used in high-performance hash maps (e.g., similar principles in Java's ConcurrentHashMap
    // spread function or Boost's hash_combine) to diffuse bits without heavy arithmetic.
    // We rotate by 29 (a prime number) to avoid alignment with byte boundaries.
    // https://www.jucs.org/jucs_5_1/rotation_symmetric_functions_and/Pieprzyk_J.pdf
    return ino ^ ((index << 29) | (index >> 35));
}

static __always_inline u64 get_folio_id_from_folio(struct folio *folio) {
    return get_folio_id(folio->mapping->host->i_ino, folio->index);
}

static __always_inline void get_hashes(u64 key, u32 *h) {
    u64 hash = hash_64(key);
    u32 h1 = (u32)hash;
    u32 h2 = (u32)(hash >> 32);

    for (int i = 0; i < NUM_HASH_FUNCTIONS; i++) {
        h[i] = h1 + i * h2;
    }
}

// Doorkeeper operations
static __always_inline bool doorkeeper_contains(u32 *h) {
    for (int i = 0; i < NUM_HASH_FUNCTIONS; i++) {
        u32 idx = h[i] % DOORKEEPER_SIZE;
        u32 word_idx = idx / NUM_BITS(u64);
        u32 bit_idx  = idx % NUM_BITS(u64);

        u64 *val = bpf_map_lookup_elem(&doorkeeper_map, &word_idx);
        if (!val) return false;
        if (!(*val & (1ULL << bit_idx))) return false;
    }
    return true;
}

static __always_inline void doorkeeper_add(u32 *h) {
    for (int i = 0; i < NUM_HASH_FUNCTIONS; i++) {
        u32 idx = h[i] % DOORKEEPER_SIZE;
        u32 word_idx = idx / NUM_BITS(u64);
        u32 bit_idx  = idx % NUM_BITS(u64);

        u64 *val = bpf_map_lookup_elem(&doorkeeper_map, &word_idx);
        if (val) {
            __sync_fetch_and_or(val, (1ULL << bit_idx));
        }
    }
}

// CBF operations
static int reset_cbf_loop_callback(u32 index, void *ctx) {
    u32 key = index;
    u64 *val = bpf_map_lookup_elem(&cbf_map, &key);
    if (!val) return 0;

    // We need to halve each 4-bit counter in the 64-bit word
    u64 v = *val;
    u64 new_val = 0;
    
    #pragma unroll
    for (int i = 0; i < NUM_BITS(u64) / BITS_PER_COUNTER; i++) {
        u32 shift = i * BITS_PER_COUNTER;
        u64 counter = (v >> shift) & COUNTER_MASK;
        counter >>= 1;
        new_val |= (counter << shift);
    }
    
    *val = new_val;
    return 0;
}

static int clear_doorkeeper_loop_callback(u32 index, void *ctx) {
    u32 key = index;
    u64 *val = bpf_map_lookup_elem(&doorkeeper_map, &key);
    if (!val) return 0;
    *val = 0;
    return 0;
}

static __always_inline void cbf_reset() {
    bpf_loop(CBF_MAP_SIZE, reset_cbf_loop_callback, NULL, 0);
    bpf_loop(DOORKEEPER_MAP_SIZE, clear_doorkeeper_loop_callback, NULL, 0);
}

static __always_inline bool cbf_add(u32 *h) {
    u32 min_val = 0xFFFFFFFF;
    u32 vals[NUM_HASH_FUNCTIONS];

    // 1. Find min value
    #pragma unroll
    for (int i = 0; i < NUM_HASH_FUNCTIONS; i++) {
        u32 idx      = h[i] % CBF_SIZE;
        u32 word_idx = idx / (NUM_BITS(u64) / BITS_PER_COUNTER);
        u32 shift    = (idx % (NUM_BITS(u64) / BITS_PER_COUNTER)) * BITS_PER_COUNTER;

        u64 *val_ptr = bpf_map_lookup_elem(&cbf_map, &word_idx);
        if (val_ptr) {
            vals[i] = (*val_ptr >> shift) & COUNTER_MASK;
            if (vals[i] < min_val) min_val = vals[i];
        } else {
            vals[i] = 0;
            min_val = 0;
        }
    }

    // 2. Update counters
    u32 new_min = min_val + 1;
    if (new_min > COUNTER_MASK) new_min = COUNTER_MASK;

    #pragma unroll
    for (int i = 0; i < NUM_HASH_FUNCTIONS; i++) {
        if (vals[i] < new_min) {
            u32 idx      = h[i] % CBF_SIZE;
            u32 word_idx = idx / (NUM_BITS(u64) / BITS_PER_COUNTER);
            u32 shift    = (idx % (NUM_BITS(u64) / BITS_PER_COUNTER)) * BITS_PER_COUNTER;

            u64 *val_ptr = bpf_map_lookup_elem(&cbf_map, &word_idx);
            if (val_ptr) {
                // TODO: can we safely ignore overflow into the next counter?
                __sync_fetch_and_add(val_ptr, 1ULL << shift);
            }
        }
    }

    // 3. Global reset logic
    __sync_fetch_and_add(&global_counter, 1);
    if (global_counter >= (1ULL << SAMPLE_SIZE_BITS)) {
        global_counter = 0;
        cbf_reset();
    }

    return new_min >= COUNTER_MASK;
}

static __always_inline u32 cbf_estimate(u32 *h) {
    u32 min_val = 0xFFFFFFFF;
    for (int i = 0; i < NUM_HASH_FUNCTIONS; i++) {
        u32 idx      = h[i] % CBF_SIZE;
        u32 word_idx = idx / (NUM_BITS(u64) / BITS_PER_COUNTER);
        u32 shift    = (idx % (NUM_BITS(u64) / BITS_PER_COUNTER)) * BITS_PER_COUNTER;

        u64 *val_ptr = bpf_map_lookup_elem(&cbf_map, &word_idx);
        if (val_ptr) {
            u32 val = (*val_ptr >> shift) & COUNTER_MASK;
            if (val < min_val) min_val = val;
        } else {
            return 0;
        }
    }
    return min_val;
}

static __always_inline u32 tinylfu_estimate(u64 addr) {
    u32 h[NUM_HASH_FUNCTIONS];
    get_hashes(addr, h);

    u32 estimate = cbf_estimate(h);
    if (doorkeeper_contains(h)) {
        estimate += 1;
    }
    return estimate;
}

/******************************************************************************
 * MRU Backend Implementation *************************************************
 *****************************************************************************/

__u64 mru_list;

inline bool is_ino_relevant(u64 ino)
{
	return inode_in_watchlist(ino);
}

inline bool is_folio_relevant(struct folio *folio)
{
	if (!folio) {
		return false;
	}
	if (folio->mapping == NULL) {
		return false;
	}
	if (folio->mapping->host == NULL) {
		return false;
	}

	return is_ino_relevant(folio->mapping->host->i_ino);
}

static int iterate_mru(int idx, struct cache_ext_list_node *node)
{
	if ((idx < 200) && (!folio_test_uptodate(node->folio) || !folio_test_lru(node->folio))) {
		return CACHE_EXT_CONTINUE_ITER;
	}
	return CACHE_EXT_EVICT_NODE;
}

static int mru_init(struct mem_cgroup *memcg)
{
	dbg_printk("cache_ext: Hi from the mru_init hook! :D\n");
	mru_list = bpf_cache_ext_ds_registry_new_list(memcg);
	if (mru_list == 0) {
		dbg_printk("cache_ext: Failed to create mru_list\n");
		return -1;
	}
	dbg_printk("cache_ext: Created mru_list: %llu\n", mru_list);
	return 0;
}

static void mru_folio_added(struct folio *folio)
{
	dbg_printk("cache_ext: Hi from the mru_folio_added hook! :D\n");
	if (!is_folio_relevant(folio)) {
		return;
	}

	int ret = bpf_cache_ext_list_add(mru_list, folio);
	    if (ret != 0) {
        dbg_printk("cache_ext: Failed to add folio to mru_list, ret=%d\n", ret);
        return;
    }
	dbg_printk("cache_ext: Added folio to mru_list\n");
}

static void mru_folio_accessed(struct folio *folio)
{
	int ret;
	dbg_printk("cache_ext: Hi from the mru_folio_accessed hook! :D\n");

	if (!is_folio_relevant(folio)) {
		return;
	}

	ret = bpf_cache_ext_list_move(mru_list, folio, false);
	if (ret != 0) {
		dbg_printk("cache_ext: Failed to move folio to mru_list head\n");
		return;
	}

	dbg_printk("cache_ext: Moved folio to mru_list tail\n");
}

static void mru_folio_evicted(struct folio *folio)
{
	dbg_printk("cache_ext: Hi from the mru_folio_evicted hook! :D\n");
	bpf_cache_ext_list_del(folio);
}

static void mru_evict_folios(struct cache_ext_eviction_ctx *eviction_ctx,
	       struct mem_cgroup *memcg)
{
	dbg_printk("cache_ext: Hi from the mru_evict_folios hook! :D\n");
	int ret = bpf_cache_ext_list_iterate(memcg, mru_list, iterate_mru,
					     eviction_ctx);
	// Check that the right amount of folios were evicted
	if (ret < 0) {
		dbg_printk("cache_ext: Failed to evict folios\n");
	}
	if (eviction_ctx->request_nr_folios_to_evict > eviction_ctx->nr_folios_to_evict) {
		dbg_printk("cache_ext: Didn't evict enough folios. Requested: %d, Evicted: %d\n",
			   eviction_ctx->request_nr_folios_to_evict,
			   eviction_ctx->nr_folios_to_evict);
	}
}

/******************************************************************************
 * TinyLFU Implementation *****************************************************
 *****************************************************************************/

s32 BPF_STRUCT_OPS_SLEEPABLE(tinylfu_init, struct mem_cgroup *memcg)
{
    dbg_printk("cache_ext: TinyLFU: Initialize TinyLFU\n");
    return mru_init(memcg);
}

void BPF_STRUCT_OPS(
    tinylfu_evict_folios,
    struct cache_ext_eviction_ctx *eviction_ctx,
    struct mem_cgroup *memcg
) {
    mru_evict_folios(eviction_ctx, memcg);
}

void BPF_STRUCT_OPS(tinylfu_folio_evicted, struct folio *folio) {
    dbg_printk("cache_ext: TinyLFU: Evicted Folio %ld\n", folio->mapping->host->i_ino);
    mru_folio_evicted(folio);
}

void BPF_STRUCT_OPS(tinylfu_folio_added, struct folio *folio) {
    if (!is_folio_relevant(folio))
        return;

    dbg_printk("cache_ext: TinyLFU: Added %ld\n", folio->mapping->host->i_ino);
    mru_folio_added(folio);
}

void BPF_STRUCT_OPS(tinylfu_folio_accessed, struct folio *folio) {
    if (!is_folio_relevant(folio))
        return;

    dbg_printk("cache_ext: TinyLFU: Access:    %ld", folio->mapping->host->i_ino);

    u64 id = get_folio_id_from_folio(folio);
    u32 h[NUM_HASH_FUNCTIONS];
    get_hashes(id, h);

    if (!doorkeeper_contains(h)) {
        doorkeeper_add(h);
    } else {
        cbf_add(h);
    }

    mru_folio_accessed(folio);
}

/*
 * Returns:
 * - False: Admits folio and uses page cache normally
 * - True:  Does not admit folio and causes that folio 
 *          to bypass the page cache.
 * 
 * This might seem counter-intuitive, but that's how it is explained
 * by the authors of cache_ext in 
 * damon_cache_ext/rocksdb/cachestream/bpf/cachestream_admit_hook.bpf.c
 */
bool BPF_STRUCT_OPS(tinylfu_folio_admission, struct cache_ext_admission_ctx *admission_ctx) {
    u64 new_id = get_folio_id(admission_ctx->ino, admission_ctx->offset >> PAGE_SHIFT);
    u64 victim_id = get_folio_id(admission_ctx->victim_ino, admission_ctx->victim_page_offset);

    if (victim_id == 0) {
        // No victim (cache likely not full), always admit.
        return false;
    }

    u32 new_est = tinylfu_estimate(new_id);
    u32 victim_est = tinylfu_estimate(victim_id);

    dbg_printk(
        "cache_ext: TinyLFU: Estimate New %u vs Victim %u, admitting=%d\n",
        new_est, victim_est, new_est > victim_est
    );

    // If new_est > victim_est, we want to ADMIT (return false).
    // Otherwise, we want to REJECT (return true).
    return true;
}

bool BPF_STRUCT_OPS(tinylfu_filter_inode, u64 ino)
{
    bool res = is_ino_relevant(ino);
    dbg_printk("cache_ext: TinyLFU: Filter: %llu -> is_relevant: %d\n", ino, res);
    return res;
}

SEC(".struct_ops.link")
struct cache_ext_ops tinylfu_ops = {
    .init = (void *)tinylfu_init,
    .evict_folios = (void *)tinylfu_evict_folios,
    .folio_accessed = (void *)tinylfu_folio_accessed,
    .folio_evicted = (void *)tinylfu_folio_evicted,
    .folio_added = (void *)tinylfu_folio_added,
    .admit_folio = (void *)tinylfu_folio_admission,
    .filter_inode = (void *)tinylfu_filter_inode,
};
