#!/bin/bash
# disable-mglru.sh

if [ ! -f /sys/kernel/mm/lru_gen/enabled ]; then
    echo "MGLRU not present, skipping disable."
    exit 0
fi

echo 'n' | sudo tee /sys/kernel/mm/lru_gen/enabled > /dev/null

# Check that it was successfully disabled
lru_val=$(cat /sys/kernel/mm/lru_gen/enabled)
[[ "$lru_val" == "0x0000" ]]
