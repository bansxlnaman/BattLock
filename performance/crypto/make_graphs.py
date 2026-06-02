import pandas as pd
import matplotlib.pyplot as plt
import re

results = pd.read_csv("performance/crypto/results.csv")

# Graph 1 Authentication Latency

auth_metrics = [
    "certificate_verify",
    "challenge_generation",
    "signature_generation",
    "signature_verification",
]

auth_df = results[results.metric.isin(auth_metrics)]

plt.figure(figsize=(8, 5))

plt.bar(auth_df["metric"], auth_df["value"])

plt.ylabel("Milliseconds")

plt.title("BattLock Authentication Latency")

plt.tight_layout()

plt.savefig("performance/crypto/auth_latency.png")

plt.close()

# Graph 2 Message Sizes

message_metrics = [
    "batteryhello_size",
    "authchallenge_size",
    "authresponse_size",
    "authsuccess_size",
    "telemetry_size",
]

msg_df = results[results.metric.isin(message_metrics)]

plt.figure(figsize=(8, 5))

plt.bar(msg_df["metric"], msg_df["value"])

plt.ylabel("Bytes")

plt.title("BattLock Message Sizes")

plt.tight_layout()

plt.savefig("performance/crypto/message_sizes.png")

plt.close()

# Graph 3 Security Overhead

sizes = {"Auth Messages": 85 + 111 + 149 + 94, "Telemetry": 209}

plt.figure(figsize=(6, 6))

plt.pie(sizes.values(), labels=sizes.keys(), autopct="%1.1f%%")

plt.title("Communication Overhead Distribution")

plt.savefig("performance/crypto/security_overhead.png")

plt.close()

# Graph 4 Battery Scalability

import re

scalability = results[results.metric.str.match(r"^battery_\d+$")].copy()

scalability["count"] = scalability["metric"].str.extract(r"battery_(\d+)").astype(int)

scalability = scalability.sort_values("count")

plt.figure(figsize=(8, 5))

plt.plot(scalability["count"], scalability["value"], marker="o")

plt.xlabel("Number of Batteries")

plt.ylabel("Verification Time (ms)")

plt.title("Certificate Verification Scalability")

plt.grid(True)

plt.tight_layout()

plt.savefig("performance/crypto/scalability.png")

plt.close()
