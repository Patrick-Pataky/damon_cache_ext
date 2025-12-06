#!/usr/bin/env bash

rm -f "../results/filesearch_results.json"
rm -f "../results/filesearch_results_mglru.json"

sudo sync
sudo sh -c "echo 1 > /proc/sys/vm/drop_caches"
sudo swapoff -a

sudo cgdelete 'memory:cache_ext_test'
sudo cgcreate -g 'memory:cache_ext_test'
sudo sh -c "echo 1073741824 > /sys/fs/cgroup/cache_ext_test/memory.max"

sudo /home/ubuntu/damon_cache_ext/policies/cache_ext_tinylfu.out \
    --watch_dir "/home/ubuntu/linux" \
    --cgroup_path "/sys/fs/cgroup/cache_ext_test" &

POLICY=$!

sleep 2

sudo taskset -c 0-7 cgexec -g 'memory:cache_ext_test' \
    /bin/sh -c "for i in $(seq 1 10); do rg write /home/ubuntu/linux > /dev/null; done"

sudo kill -2 $POLICY
sudo rm /sys/fs/bpf/cache_ext/scan_pids

sudo cat /sys/kernel/debug/tracing/trace_pipe > trace
