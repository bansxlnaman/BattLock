from crypto.certs.root_ca import RootCA

from crypto.certs.certificate import (
    create_certificate
)

from crypto.crypto_utils.signatures import (
    generate_keypair,
    sign_message
)

from crypto.crypto_utils.key_serialization import (
    serialize_public_key
)

from crypto.auth.challenge import (
    create_challenge
)

from crypto.auth.verifier import (
    verify_challenge_response
)


def test_spoofing_attack_detected():

    root_ca = RootCA()

    _, battery_public_key = generate_keypair()

    certificate = create_certificate(
        root_ca=root_ca,
        battery_id="BAT001",
        manufacturer_id="THAPAR",
        battery_public_key=serialize_public_key(
            battery_public_key
        ),
        issue_date="2026-06-01",
        expiry_date="2031-06-01"
    )

    challenge = create_challenge()

    attacker_private_key, _ = generate_keypair()

    challenge_data = (
        challenge.nonce
        + str(challenge.timestamp).encode()
    )

    fake_signature = sign_message(
        attacker_private_key,
        challenge_data
    )

    result = verify_challenge_response(
        certificate,
        challenge,
        fake_signature
    )

    assert result is False

    print(
        "\n[PASS]"
        " Spoofing attack detected -"
        " attacker signature rejected"
    )


if __name__ == "__main__":

    test_spoofing_attack_detected()
