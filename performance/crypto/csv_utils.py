import csv
import os

CSV_FILE = "performance/crypto/results.csv"


def update_metric(metric, value, unit):

    rows = []

    if os.path.exists(CSV_FILE):

        with open(CSV_FILE, "r", newline="") as file:

            rows = list(csv.DictReader(file))

    updated = False

    for row in rows:

        if row["metric"] == metric:

            row["value"] = value
            row["unit"] = unit

            updated = True

    if not updated:

        rows.append({"metric": metric, "value": value, "unit": unit})

    with open(CSV_FILE, "w", newline="") as file:

        writer = csv.DictWriter(file, fieldnames=["metric", "value", "unit"])

        writer.writeheader()
        writer.writerows(rows)
