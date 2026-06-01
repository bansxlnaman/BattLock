from crypto.certs.root_ca import RootCA

from crypto.certs.certificate import create_certificate, verify_certificate

from crypto.crypto_utils.signatures import generate_keypair, sign_message

from crypto.crypto_utils.key_serialization import serialize_public_key

from crypto.auth.challenge import create_challenge

from crypto.auth.verifier import verify_challenge_response

from crypto.auth.session import create_session


def run_test():

    print("\n=== BattLock Authentication ===\n")

    root_ca = RootCA()

    battery_private_key, battery_public_key = generate_keypair()

    certificate = create_certificate(
        root_ca=root_ca,
        battery_id="BAT001",
        manufacturer_id="THAPAR",
        battery_public_key=serialize_public_key(battery_public_key),
        issue_date="2026-06-01",
        expiry_date="2031-06-01",
    )

    print("Certificate:", verify_certificate(certificate, root_ca.public_key))

    challenge = create_challenge()

    challenge_data = challenge.nonce + str(challenge.timestamp).encode()

    signature = sign_message(battery_private_key, challenge_data)

    auth_result = verify_challenge_response(certificate, challenge, signature)

    print("Authentication:", auth_result)

    if auth_result:

        session = create_session(certificate.battery_id)

        print("Session ID:", session.session_id)


if __name__ == "__main__":
    run_test()
