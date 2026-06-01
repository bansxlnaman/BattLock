from crypto.crypto_utils.signatures import (
    verify_signature
)

from crypto.crypto_utils.key_serialization import (
    deserialize_public_key
)


def verify_challenge_response(
    certificate,
    challenge,
    signature
):

    public_key = deserialize_public_key(
        certificate.public_key
    )

    challenge_data = (
        challenge.nonce
        + str(challenge.timestamp).encode()
    )

    return verify_signature(
        public_key,
        challenge_data,
        signature
    )