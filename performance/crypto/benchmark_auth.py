import time

from crypto.certs.root_ca import RootCA
from crypto.certs.certificate import create_certificate, verify_certificate

from crypto.crypto_utils.signatures import generate_keypair, sign_message

from crypto.crypto_utils.key_serialization import serialize_public_key

from crypto.auth.challenge import create_challenge
from crypto.auth.verifier import verify_challenge_response

from performance.crypto.csv_utils import update_metric

ITERATIONS = 1000


def benchmark():

    root_ca = RootCA()

    battery_private_key, battery_public_key = generate_keypair()

    certificate = create_certificate(
        root_ca=root_ca,
        battery_id="BAT001",
        manufacturer_id="THAPAR",
        battery_public_key=serialize_public_key(battery_public_key),
        issue_date="2026-01-01",
        expiry_date="2031-01-01",
    )

    cert_total = 0
    challenge_total = 0
    sign_total = 0
    verify_total = 0
    auth_total = 0

    for _ in range(ITERATIONS):

        start = time.perf_counter()

        verify_certificate(certificate, root_ca.public_key)

        cert_total += time.perf_counter() - start

        start = time.perf_counter()

        challenge = create_challenge()

        challenge_total += time.perf_counter() - start

        challenge_data = challenge.nonce + str(challenge.timestamp).encode()

        start = time.perf_counter()

        signature = sign_message(battery_private_key, challenge_data)

        sign_total += time.perf_counter() - start

        start = time.perf_counter()

        verify_challenge_response(certificate, challenge, signature)

        verify_total += time.perf_counter() - start

        start = time.perf_counter()

        verify_certificate(certificate, root_ca.public_key)

        verify_challenge_response(certificate, challenge, signature)

        auth_total += time.perf_counter() - start

    update_metric("certificate_verify", (cert_total / ITERATIONS) * 1000, "ms")

    update_metric("challenge_generation", (challenge_total / ITERATIONS) * 1000, "ms")

    update_metric("signature_generation", (sign_total / ITERATIONS) * 1000, "ms")

    update_metric("signature_verification", (verify_total / ITERATIONS) * 1000, "ms")

    update_metric("total_authentication", (auth_total / ITERATIONS) * 1000, "ms")


if __name__ == "__main__":
    benchmark()
