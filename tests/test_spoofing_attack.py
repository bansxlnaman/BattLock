from crypto.certs.root_ca import RootCA

from crypto.certs.certificate import (
    create_certificate
)

from crypto.crypto_utils.signatures import (
    generate_keypair
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

from can.attacks.spoofing_attack import (
    SpoofingAttack
)


root_ca = RootCA()

battery_private_key, battery_public_key = generate_keypair()

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

attack = SpoofingAttack()

fake_signature = attack.create_fake_signature(
    challenge
)

result = verify_challenge_response(
    certificate,
    challenge,
    fake_signature
)

if result:

    print("SPOOFING SUCCEEDED")

else:

    print("SPOOFING ATTACK DETECTED")