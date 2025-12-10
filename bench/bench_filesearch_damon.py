import logging
import os
from time import time
from typing import List, Dict

from bench_lib_damon import *

log = logging.getLogger(__name__)

# These only run on error
CLEANUP_TASKS = []


class FileSearchBenchmark(BenchmarkFramework):
    def __init__(self, benchresults_cls=BenchResults, cli_args=None):
        super().__init__("filesearch_benchmark", benchresults_cls, cli_args)
        # Removed CacheExtPolicy initialization

    def add_arguments(self, parser: argparse.ArgumentParser):
        parser.add_argument(
            "--data-dir",
            type=str,
            required=True,
            help="Data directory",
        )
        # Removed --policy-loader argument

    def generate_configs(self, configs: List[Dict]) -> List[Dict]:
        configs = add_config_option("passes", [20], configs)
        configs = add_config_option("cgroup_size", [1 * GiB], configs)
        if self.args.default_only:
            configs = add_config_option(
                "cgroup_name", [BASELINE_TEST_CGROUP], configs
            )

        else:
            configs = add_config_option(
                "cgroup_name",
                [BASELINE_TEST_CGROUP, DAMON_TEST_CGROUP],
                configs,
            )

        configs = add_config_option("benchmark", ["filesearch"], configs)
        configs = add_config_option(
            "iteration", list(range(1, self.args.iterations + 1)), configs
        )
        return configs

    def before_benchmark(self, config):
        drop_page_cache()
        disable_swap()
        disable_smt()
        if config["cgroup_name"] == DAMON_TEST_CGROUP:
            recreate_damon_test_cgroup(limit_in_bytes=config["cgroup_size"])
            # Removed CacheExtPolicy start
        else:
            recreate_baseline_cgroup(limit_in_bytes=config["cgroup_size"])
        self.start_time = time()

    def benchmark_cmd(self, config):
        pattern = "write"
        data_dir = self.args.data_dir
        rg_cmd = f"rg {pattern} {data_dir}"
        repeated_rg_cmd = (
            f"for i in $(seq 1 {config['passes']}); do {rg_cmd} > /dev/null; done"
        )
        cmd = [
            "cgexec",
            "-g",
            "memory:%s" % config["cgroup_name"],
            "/bin/sh",
            "-c",
            repeated_rg_cmd
        ]
        return cmd

    def after_benchmark(self, config):
        self.end_time = time()
        if config["cgroup_name"] == DAMON_TEST_CGROUP:
            # Stop DAMON if needed, though recreate_damon_test_cgroup handles start
            # and delete_cgroup handles stop implicitly via damo stop if we added it there.
            # But bench_lib.py delete_cgroup calls damo stop.
            pass
        # Removed CacheExtPolicy stop
        enable_smt()

    def parse_results(self, stdout: str) -> BenchResults:
        results = {"runtime_sec": self.end_time - self.start_time}
        return BenchResults(results)


def main():
    global log
    logging.basicConfig(level=logging.DEBUG)
    global log
    # To ensure that writeback keeps up with the benchmark
    filesearch_bench = FileSearchBenchmark()
    # Check that trace data dir exists
    if not os.path.exists(filesearch_bench.args.data_dir):
        raise Exception(
            "Filesearch data directory not found: %s" % filesearch_bench.args.data_dir
        )
    log.info("Filesearch data directory: %s", filesearch_bench.args.data_dir)
    filesearch_bench.benchmark()


if __name__ == "__main__":
    try:
        logging.basicConfig(level=logging.INFO)
        main()
    except Exception as e:
        log.error("Error in main: %s", e)
        log.info("Cleaning up")
        for task in CLEANUP_TASKS:
            task()
        log.error("Re-raising exception")
        raise e
