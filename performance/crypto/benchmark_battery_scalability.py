import time

from crypto.certs.root_ca import RootCA
from crypto.certs.certificate import create_certificate, verify_certificate

from crypto.crypto_utils.signatures import generate_keypair

from crypto.crypto_utils.key_serialization import serialize_public_key

from performance.crypto.csv_utils import update_metric

BATTERY_COUNTS = [1, 10, 50, 100, 500]


def benchmark():

    root_ca = RootCA()

    print("\n=== BATTERY SCALABILITY ===")

    for count in BATTERY_COUNTS:

        certificates = []

        for i in range(count):

            _, public_key = generate_keypair()

            cert = create_certificate(
                root_ca=root_ca,
                battery_id=f"BAT{i}",
                manufacturer_id="THAPAR",
                battery_public_key=serialize_public_key(public_key),
                issue_date="2026-01-01",
                expiry_date="2031-01-01",
            )

            certificates.append(cert)

        verify_certificate(certificates[0], root_ca.public_key)

        start = time.perf_counter()

        for cert in certificates:

            verify_certificate(cert, root_ca.public_key)

        end = time.perf_counter()

        total_ms = (end - start) * 1000

        avg_ms = total_ms / count

        print(f"\nBatteries: {count}")

        print(f"Total Verification: {total_ms:.4f} ms")

        print(f"Average: {avg_ms:.4f} ms")

        update_metric(f"battery_{count}", round(total_ms, 4), "ms")


if __name__ == "__main__":
    benchmark()
