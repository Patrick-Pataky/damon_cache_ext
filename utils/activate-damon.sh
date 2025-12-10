#!/usr/bin/env bash

set -euo pipefail

check_damo_install(){
    if ! command -v damo &> /dev/null; then
        echo "damo could not be found, please install it first."
        return 1
    fi

    if [ ! -d /sys/module/damon_reclaim ]; then
        echo "damon_reclaim module is not loaded. Please load it first."
        return 1
    fi
}

damon_reclaim_set(){
    if [ "$#" -ne 2 ]; then
        echo "Usage: damon_reclaim <value> <parameter_name>"
        return 1
    fi

    echo "$1" | sudo tee /sys/module/damon_reclaim/parameters/"$2"
}

damon_reclaim_show_parameters(){
    sudo damo reclaim
}

damon_reclaim_enable(){
#    damon_reclaim_set 1 enabled
#    damon_reclaim_set 0 monitor_region_start
#    damon_reclaim_set $((1024*1024*1024*60)) monitor_region_end
#    damon_reclaim_set $((1024*1024*1024)) quota_sz
#    damon_reclaim_set 50 quota_ms

sudo damo start --kdamonds /home/damon/project/damon_cache_ext/utils/damon_config.json
}

damon_reclaim_disable(){
#    damon_reclaim_set 0 enabled
sudo damo stop
}

damon_reclaim_commit(){
    damon_reclaim_set 1 commit_inputs
}

# Profile: Normal
damon_reclaim_set_c1() {
    damon_reclaim_set 120000000 min_age
    damon_reclaim_set 999 wmarks_high
    damon_reclaim_set 995 wmarks_mid
    damon_reclaim_set 1 wmarks_low
}

# Profile: Plus Aggressive
damon_reclaim_set_c2() {
    damon_reclaim_set 10000000 min_age
    damon_reclaim_set 999 wmarks_high
    damon_reclaim_set 995 wmarks_mid
    damon_reclaim_set 1 wmarks_low
}

# Profile: Very Aggressive
damon_reclaim_set_c3() {
    damon_reclaim_set 1000000 min_age
    damon_reclaim_set 999 wmarks_high
    damon_reclaim_set 995 wmarks_mid
    damon_reclaim_set 1 wmarks_low
}

damon_reclaim_set_config(){
    case "$1" in
        1)
            damon_reclaim_set_c1
            ;;
        2)
            damon_reclaim_set_c2
            ;;
        3)
            damon_reclaim_set_c3
            ;;
        *)
            echo "Unknown config profile: $1"
            echo "Available profiles: 1, 2, 3"
            return 1
            ;;
    esac

    damon_reclaim_commit
}

_damon_params_complete() {
    local cur prev opts
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"

    opts="kdamond_pid commit_inputs enabled min_age quota_ms" \
            "quota_sz quota_reset_interval_ms wmarks_interval" \
            "wmarks_high wmarks_mid wmarks_low sample_interval" \
            "aggr_interval min_nr_regions max_nr_regions" \
            "monitor_region_start monitor_region_end skip_anon" \
            "quota_mem_pressure_us quota_autotune_feedback"

    if [[ $COMP_CWORD -eq 2 ]]; then
        COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
        return 0
    fi
}

check_damo_install || return 1
complete -F _damon_params_complete damon_reclaim_set
