from bench_lib import *
import logging
import subprocess

log = logging.getLogger(__name__)

DAMON_TEST_CGROUP = "damon_test"
BASELINE_TEST_CGROUP = "baseline_test"

def recreate_damon_test_cgroup(cgroup=DAMON_TEST_CGROUP, limit_in_bytes=2 * GiB):
    delete_cgroup(cgroup)
    # Create damon_test cgroup
    run(["sudo", "cgcreate", "-g", f"memory:{cgroup}"])

    # Set memory limit for damon_test cgroup
    run(
        [
            "sudo",
            "sh",
            "-c",
            "echo %d > /sys/fs/cgroup/%s/memory.max" % (limit_in_bytes, cgroup),
        ]
    )

    log.info(
        "damon_test cgroup %s created with limit %s",
        cgroup,
        format_bytes_str(limit_in_bytes),
    )

    run(
        [
            "sudo",
            "sh",
            "-c",
            "sudo damo start --kdamonds /home/damon/project/damon_cache_ext/utils/damon_config_damon_test.json",
        ]
    )

def recreate_baseline_cgroup(cgroup=BASELINE_TEST_CGROUP, limit_in_bytes=2 * GiB):
    delete_cgroup(cgroup)
    # Create baseline cgroup
    run(["sudo", "cgcreate", "-g", f"memory:{cgroup}"])

    # Set memory limit for baseline cgroup
    run(
        [
            "sudo",
            "sh",
            "-c",
            "echo %d > /sys/fs/cgroup/%s/memory.max" % (limit_in_bytes, cgroup),
        ]
    )
    
    # Ensure DAMON is stopped (just in case)
    with suppress(subprocess.CalledProcessError):
        run(["sudo", "damo", "stop"])

    log.info(
        "baseline cgroup %s created with limit %s (NO DAMON)",
        cgroup,
        format_bytes_str(limit_in_bytes),
    )
