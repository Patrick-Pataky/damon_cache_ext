#!/bin/bash

CGROUP="cache_ext_test"
GiB=2**30
CGROUP_SIZE=1*$Gib

echo "Creating cgroup ..."
sudo cgcreate -g memory:$CGROUP
sudo sh -c echo "$CGROUP_SIZE" > /sys/fs/cgroup/$CGROUP/memory.max

taskset -c 0-4 sudo cgexec -g memory:$CGROUP /bin/sh -c rg write . > /dev/null

echo "Deleting cgroup ..."
sudo cgdelete memory:$CGROUP
