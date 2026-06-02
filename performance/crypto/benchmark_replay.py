import time

from crypto.counters.replay_protection import ReplayProtection

from performance.crypto.csv_utils import update_metric

ITERATIONS = 100000


def benchmark():

    guard = ReplayProtection()

    start = time.perf_counter()

    for i in range(1, ITERATIONS):

        guard.validate(i)

    end = time.perf_counter()

    total_ms = (end - start) * 1000

    avg_us = (end - start) / ITERATIONS * 1000000

    update_metric("replay_protection", total_ms, "ms")

    print(f"Average Validation: {avg_us:.4f} us")


if __name__ == "__main__":
    benchmark()
