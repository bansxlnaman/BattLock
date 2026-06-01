from datetime import date

from crypto.certs.root_ca import RootCA
from crypto.certs.certificate import create_certificate, verify_certificate

from crypto.crypto_utils.signatures import generate_keypair
from crypto.crypto_utils.key_serialization import serialize_public_key


def run_test():

    root_ca = RootCA()

    battery_private_key, battery_public_key = generate_keypair()

    certificate = create_certificate(
        root_ca=root_ca,
        battery_id="BAT001",
        manufacturer_id="THAPAR",
        # battery_public_key=battery_public_key.public_bytes(
        #    encoding=3,
        #   format=0
        # )
        battery_public_key=serialize_public_key(battery_public_key),
        issue_date="2026-06-01",
        expiry_date="2031-06-01",
    )

    result = verify_certificate(certificate, root_ca.public_key)

    print("Certificate Valid:", result)


if __name__ == "__main__":
    run_test()
