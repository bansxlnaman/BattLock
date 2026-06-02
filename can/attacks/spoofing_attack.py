from crypto.crypto_utils.signatures import generate_keypair
from crypto.crypto_utils.signatures import sign_message


class SpoofingAttack:

    def create_fake_signature(self, challenge):

        fake_private_key, _ = generate_keypair()

        challenge_data = (
            challenge.nonce +
            str(challenge.timestamp).encode()
        )

        return sign_message(
            fake_private_key,
            challenge_data
        )