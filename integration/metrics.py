import time
import json
import csv
import psutil
import os

class MetricsCollector:

    def __init__(self):

        self.metrics = {}

        self.can_latencies = []

        self.payload_sizes = []

        self.total_messages = 0

        self.total_bytes = 0

        self.process = psutil.Process(
            os.getpid()
        )

    def start(self, name):

        self.metrics[name] = time.perf_counter()

    def stop(self, name):

        self.metrics[name] = (
            time.perf_counter()
            - self.metrics[name]
        )

    def record_can(
        self,
        payload_size,
        latency
    ):

        self.total_messages += 1

        self.total_bytes += payload_size

        self.payload_sizes.append(
            payload_size
        )

        self.can_latencies.append(
            latency
        )

    def report(self):

        return {

            **self.metrics,

            "total_messages":
                self.total_messages,

            "total_bytes":
                self.total_bytes,

            "average_payload":
                (
                    sum(self.payload_sizes)
                    / len(self.payload_sizes)
                )
                if self.payload_sizes else 0,

            "largest_payload":
                (
                    max(self.payload_sizes)
                )
                if self.payload_sizes else 0,

            "smallest_payload":
                (
                    min(self.payload_sizes)
                )
                if self.payload_sizes else 0,

            "average_latency_ms":
                (
                    sum(self.can_latencies)
                    / len(self.can_latencies)
                )
                if self.can_latencies else 0,

            "max_latency_ms":
                (
                    max(self.can_latencies)
                )
                if self.can_latencies else 0,

            "min_latency_ms":
                (
                    min(self.can_latencies)
                )
                if self.can_latencies else 0,

            "memory_mb":
                self.process.memory_info().rss
                /1024/1024
        }

    def export(self):

        report = self.report()

        with open(
            "logs/metrics.json",
            "w"
        ) as f:

            json.dump(
                report,
                f,
                indent=4
            )

        with open(
            "logs/metrics.csv",
            "w",
            newline=""
        ) as f:

            writer = csv.writer(f)

            writer.writerow(
                ["Metric","Value"]
            )

            for k,v in report.items():

                writer.writerow(
                    [k,v]
                )