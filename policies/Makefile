# Define the compiler and the flags
# See: https://stackoverflow.com/questions/76035116/cannot-use-ebpf-kptr-ref-feature
CLANG ?= clang-14
BPFTOOL ?= /usr/local/sbin/bpftool #../../tools/bpf/bpftool/bpftool

# Default Cache Size Bits (can be overridden: make CACHE_SIZE_BITS=20)
CACHE_SIZE_BITS ?= 18

CFLAGS = -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
	 -DCACHE_SIZE_BITS=$(CACHE_SIZE_BITS) \
	 -c -g -Wall
USERSPACE_CFLAGS = -O2 -fsanitize=address -g -Wall
USERSPACE_LINKER_FLAGS = -L/usr/local/lib64 -lbpf

# Define the BPF program source and the output object file
BPF_SRC = cache_ext_simple.bpf.c cache_ext_mru.bpf.c cache_ext_mglru.bpf.c
BPF_OBJ = $(BPF_SRC:.c=.o)
BPF_SKEL = $(BPF_SRC:bpf.c=skel.h)

ARCH ?= $(shell uname -m | sed 's/x86_64/x86/' \
			 | sed 's/arm.*/arm/' \
			 | sed 's/aarch64/arm64/' \
			 | sed 's/ppc64le/powerpc/' \
			 | sed 's/mips.*/mips/' \
			 | sed 's/riscv64/riscv/' \
			 | sed 's/loongarch64/loongarch/')

VMLINUX_H = vmlinux.h

# Get Clang's default includes on this system. We'll explicitly add these dirs
# to the includes list when compiling with `-target bpf` because otherwise some
# architecture-specific dirs will be "missing" on some architectures/distros -
# headers such as asm/types.h, asm/byteorder.h, asm/socket.h, asm/sockios.h,
# sys/cdefs.h etc. might be missing.
#
# Use '-idirafter': Don't interfere with include mechanics except where the
# build would have failed anyways.
CLANG_BPF_SYS_INCLUDES ?= $(shell $(CLANG) -v -E - </dev/null 2>&1 \
	| sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')

# Exclude simple, get_scan, and tinylfu itself.
TINYLFU_EXCLUDE = cache_ext_tinylfu.bpf.c cache_ext_simple.bpf.c cache_ext_get_scan.bpf.c
TINYLFU_SRCS = $(filter-out $(TINYLFU_EXCLUDE), $(wildcard cache_ext_*.bpf.c))
TINYLFU_VARIANTS = $(patsubst cache_ext_%.bpf.c, cache_ext_tiny_%.out, $(TINYLFU_SRCS))

all: 	cache_ext_mru.out cache_ext_mglru.out cache_ext_fifo.out \
		cache_ext_sampling.out cache_ext_get_scan.out cache_ext_s3fifo.out \
		cache_ext_lhd.out cache_ext_tinylfu.out \
		$(TINYLFU_VARIANTS)

$(VMLINUX_H):
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX_H)

.SECONDARY:
%.bpf.o: %.bpf.c $(VMLINUX_H) dir_watcher.bpf.h
	$(CLANG) $(CFLAGS) $(CLANG_BPF_SYS_INCLUDES) $< -o $@

.SECONDARY:
%.skel.h: %.bpf.o $(VMLINUX_H)
	$(BPFTOOL) gen skeleton $< > $@

%.out: %.c %.skel.h
	$(CLANG) $(USERSPACE_CFLAGS) $< -o $@ $(USERSPACE_LINKER_FLAGS)

# TinyLFU Variant Rules
cache_ext_tiny_%.bpf.o: cache_ext_tinylfu.bpf.c $(VMLINUX_H) dir_watcher.bpf.h cache_ext_%.bpf.c
	$(CLANG) $(CFLAGS) $(CLANG_BPF_SYS_INCLUDES) \
		-DPOLICY_BACKEND_FILE=\"cache_ext_$*.bpf.c\" \
		$< -o $@

cache_ext_tiny_%.skel.h: cache_ext_tiny_%.bpf.o
	$(BPFTOOL) gen skeleton $< name cache_ext_tinylfu_bpf > $@

cache_ext_tiny_%.out: cache_ext_tinylfu.c cache_ext_tiny_%.skel.h
	$(CLANG) $(USERSPACE_CFLAGS) \
		-DSKEL_HEADER=\"cache_ext_tiny_$*.skel.h\" \
		$< -o $@ $(USERSPACE_LINKER_FLAGS)

clean:
	rm -f *.o *.out *.skel.h $(VMLINUX_H)

.PHONY: all clean
