import time

from performance.crypto.auth_once import authenticate_once

from performance.crypto.csv_utils import update_metric

ITERATIONS = 1000


def benchmark():

    start = time.perf_counter()

    for _ in range(ITERATIONS):

        authenticate_once()

    end = time.perf_counter()

    total_time = end - start

    throughput = ITERATIONS / total_time

    update_metric("throughput", round(throughput, 2), "auth/sec")

    print("\n=== THROUGHPUT ===")

    print(f"{throughput:.2f} auth/sec")


if __name__ == "__main__":
    benchmark()
