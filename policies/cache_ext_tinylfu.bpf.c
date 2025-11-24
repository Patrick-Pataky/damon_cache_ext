#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "cache_ext_lib.bpf.h"
#include "dir_watcher.bpf.h"

char _license[] SEC("license") = "GPL";

static u64 main_list; // Temporary

/*
This method is used to make sure that we only act on pages in the concerned 
data directory (or watch dir) and ignore any pages outside.
*/
static inline bool is_folio_relevant(struct folio *folio) {
	if (!folio || !folio->mapping || !folio->mapping->host)
		return false;

	return inode_in_watchlist(folio->mapping->host->i_ino);
}

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
	if (!folio_test_uptodate(a->folio) || !folio_test_lru(a->folio))
		return CACHE_EXT_CONTINUE_ITER;

	if (folio_test_dirty(a->folio) || folio_test_writeback(a->folio))
		return CACHE_EXT_CONTINUE_ITER;

	return CACHE_EXT_EVICT_NODE;
}

void BPF_STRUCT_OPS(tinylfu_evict_folios, struct cache_ext_eviction_ctx *eviction_ctx, struct mem_cgroup *memcg)
{
	bpf_printk("cache_ext: TinyLFU: evict: Eviction Algorithm called\n");
	if (bpf_cache_ext_list_iterate(memcg, main_list, bpf_tinylfu_evict_cb, eviction_ctx) < 0) {
		bpf_printk("cache_ext: evict: Failed to iterate main_list\n");
		return;
	}
}

void BPF_STRUCT_OPS(tinylfu_folio_evicted, struct folio *folio) {
	bpf_printk("cache_ext: TinyLFU: Evicted Folio %p\n", folio);
	// TODO: Why does fifo not do anything in this hook ?
}

void BPF_STRUCT_OPS(tinylfu_folio_added, struct folio *folio) {
	bpf_printk("cache_ext: added: TinyLFU: Added Folio %p\n", folio);
	if (!is_folio_relevant(folio))
		return;

	if (bpf_cache_ext_list_add_tail(main_list, folio)) {
		bpf_printk("cache_ext: added: Failed to add folio to main_list\n");
		return;
	}
}

void BPF_STRUCT_OPS(tinylfu_folio_accessed, struct folio *folio) {
	bpf_printk("cache_ext: TinyLFU: Accessed Folio %p", folio);
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
	bpf_printk("cache_ext: admission: TinyLFU: Making Admission Decision\n");
	return false;
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
