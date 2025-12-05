#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "cache_ext_lib.bpf.h"
#include "dir_watcher.bpf.h"

char _license[] SEC("license") = "GPL";

// Constants
#define CHAR_BIT 8
#define NUM_BITS(type) (sizeof(type) * CHAR_BIT)

#define DOORKEEPER_SIZE 10240
#define CBF_SIZE 10240
#define NUM_HASH_FUNCTIONS 4
#define BITS_PER_COUNTER 4		// Must be a power of 2
#define COUNTER_MASK ((1 << BITS_PER_COUNTER) - 1)

// 1GiB
#define CACHE_SIZE_BITS 30
// 8GiB
// #define CACHE_SIZE_BITS 33

#define SAMPLE_SIZE_BITS (BITS_PER_COUNTER + CACHE_SIZE_BITS)

static u64 global_counter = 0;

// Maps
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, DOORKEEPER_SIZE / NUM_BITS(u64) + 1);
	__type(key, u32);
	__type(value, u64);
} doorkeeper_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, CBF_SIZE / (NUM_BITS(u64) / BITS_PER_COUNTER) + 1);
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
static u64 reset_cbf_callback(struct bpf_map *map, u32 *key, u64 *val, void *ctx) {
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

static u64 clear_doorkeeper_callback(struct bpf_map *map, u32 *key, u64 *val, void *ctx) {
	*val = 0;
	return 0;
}

static __always_inline void cbf_reset() {
	bpf_for_each_map_elem(&cbf_map, reset_cbf_callback, NULL, 0);
	bpf_for_each_map_elem(&doorkeeper_map, clear_doorkeeper_callback, NULL, 0);
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
	bool res = inode_in_watchlist(folio->mapping->host->i_ino);
	return res;
}

__u64 main_list;

s32 BPF_STRUCT_OPS_SLEEPABLE(tinylfu_init, struct mem_cgroup *memcg)
{
	bpf_printk("cache_ext: TinyLFU: Initialize TinyLFU\n");

	main_list = bpf_cache_ext_ds_registry_new_list(memcg);
	if (main_list == 0) {
		bpf_printk("cache_ext: init: Failed to create main_list\n");
		return -1;
	}
	bpf_printk("cache_ext: Created main_list: %llu\n", main_list);
	return 0;
}

/* 
This callback is passed to bpf_cache_ext_list_iterate and decides what to do with the current folio.
Depending on the returned value, bpf_cache_ext_list_iterate does one of the following:
- CACHE_EXT_CONTINUE_ITER	: Ignore current folio and continue iteration
- CACHE_EXT_EVICT_NODE		: Add the current folio to the eviction candidates 
							  (bpf_cache_ext_list_iterate takes care of changing the eviction context)
- CACHE_EXT_STOP_ITER		: Stops iterating, acts ~ like break in a loop.

This should not call any cache_ext_list helpers.
(see comment in linux-cache-ext/include/mm/cache_ext_ds.c before bpf_cache_ext_list_iterate)
*/
static int bpf_tinylfu_evict_cb(int idx, struct cache_ext_list_node *a)
{
	bpf_printk("cache_ext: TinyLFU: Eviction:  %ld\n", a->folio->mapping->host->i_ino);
	if (!folio_test_uptodate(a->folio) || !folio_test_lru(a->folio))
		return CACHE_EXT_CONTINUE_ITER;

	if (folio_test_dirty(a->folio) || folio_test_writeback(a->folio))
		return CACHE_EXT_CONTINUE_ITER;

	return CACHE_EXT_EVICT_NODE;
}

void BPF_STRUCT_OPS(tinylfu_evict_folios, struct cache_ext_eviction_ctx *eviction_ctx, struct mem_cgroup *memcg)
{
	if (bpf_cache_ext_list_iterate(memcg, main_list, bpf_tinylfu_evict_cb, eviction_ctx) < 0) {
		bpf_printk("cache_ext: evict: Failed to iterate main_list\n");
		return;
	}
}

void BPF_STRUCT_OPS(tinylfu_folio_evicted, struct folio *folio) {
	bpf_printk("cache_ext: TinyLFU: Evicted Folio %ld\n", folio->mapping->host->i_ino);
	// TODO: Why does fifo not do anything in this hook ?
}

void BPF_STRUCT_OPS(tinylfu_folio_added, struct folio *folio) {
	if (!is_folio_relevant(folio))
		return;

	bpf_printk("cache_ext: TinyLFU: Added %ld\n", folio->mapping->host->i_ino);

	if (bpf_cache_ext_list_add_tail(main_list, folio)) {
		//bpf_printk("cache_ext: added: Failed to add folio to main_list\n");
		return;
	}
}

static inline bool is_folio_relevant(struct folio *folio) {
	if (!folio || !folio->mapping || !folio->mapping->host)
		return false;

	return inode_in_watchlist(folio->mapping->host->i_ino);
}

void BPF_STRUCT_OPS(tinylfu_folio_accessed, struct folio *folio) {
	if (!is_folio_relevant(folio))
		return;

	bpf_printk("cache_ext: TinyLFU: Access:    %ld", folio->mapping->host->i_ino);

	u64 addr = (u64)folio; // Use folio address as key
	u32 h[NUM_HASH_FUNCTIONS];
	get_hashes(addr, h);

	if (!doorkeeper_contains(h)) {
		doorkeeper_add(h);
	} else {
		if (cbf_add(h)) {
			cbf_reset();
		}
	}
}

/*
 * Returns:
 * - False: Admits folio and uses page cache normally
 * - True:  Does not admit folio and causes that folio 
 *   	    to bypass the page cache.
 * 
 * This might seem counter-intuitive, but that's how it is explained
 * by the authors of cache_ext in 
 * damon_cache_ext/rocksdb/cachestream/bpf/cachestream_admit_hook.bpf.c
 */
bool BPF_STRUCT_OPS(tinylfu_folio_admission, struct cache_ext_admission_ctx *admission_ctx) {
	bpf_printk("cache_ext: TinyLFU: Admission: %ld \n", admission_ctx->ino);

	struct folio *new_folio = admission_ctx->new_folio;
	struct folio *victim_folio = admission_ctx->victim_folio;

	// If new folio is not relevant, admit it (bypass filter)
	if (!is_folio_relevant(new_folio))
		return true;

	u64 new_addr = (u64)new_folio;
	u64 victim_addr = (u64)victim_folio;

	u32 new_est = tinylfu_estimate(new_addr);
	u32 victim_est = tinylfu_estimate(victim_addr);

	// bpf_printk("TinyLFU: new %u, victim %u\n", new_est, victim_est);

	return new_est > victim_est;
}

SEC(".struct_ops.link")
struct cache_ext_ops tinylfu_ops = {
	.init = (void *)tinylfu_init,
	.evict_folios = (void *)tinylfu_evict_folios,
	.folio_accessed = (void *)tinylfu_folio_accessed,
	.folio_evicted = (void *)tinylfu_folio_evicted,
	.folio_added = (void *)tinylfu_folio_added,
	.admit_folio = (void *)tinylfu_folio_admission,
};
