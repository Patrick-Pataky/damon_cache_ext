#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "cache_ext_lib.bpf.h"
#include "dir_watcher.bpf.h"

char _license[] SEC("license") = "GPL";

s32 BPF_STRUCT_OPS_SLEEPABLE(tinylfu_init, struct mem_cgroup *memcg)
{
	bpf_printk("cache_ext: Initialize TinyLFU\n");
	return 0;
}

void BPF_STRUCT_OPS(tinylfu_evict_folios, struct cache_ext_eviction_ctx *eviction_ctx, struct mem_cgroup *memcg)
{
	bpf_printk("cache_ext: evict: Eviction Algorithm called\n");
}

void BPF_STRUCT_OPS(tinylfu_folio_evicted, struct folio *folio) {
	bpf_printk("cache_ext: Evicted Folio %p\n", folio);
}

void BPF_STRUCT_OPS(tinylfu_folio_added, struct folio *folio) {
	bpf_printk("cache_ext: added: Added Folio %p\n", folio);
}

void BPF_STRUCT_OPS(tinylfu_folio_accessed, struct folio *folio) {
	bpf_printk("cache_ext: Accessed Folio %p", folio);
}

bool BPF_STRUCT_OPS(tinylfu_folio_admission, struct cache_ext_admission_ctx *admission_ctx) {
	bpf_printk("cache_ext: admission: Making Admission Decision\n");
	return true;
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
