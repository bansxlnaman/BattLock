from crypto.crypto_utils.signatures import generate_keypair, sign_message

from crypto.crypto_utils.key_serialization import serialize_public_key

from crypto.certs.certificate import create_certificate

from protocol.messages.battery_hello import BatteryHello

from protocol.messages.auth_response import AuthResponse


class BatteryNode:

    def __init__(self, battery_id, manufacturer_id, root_ca):

        self.battery_id = battery_id

        self.private_key, self.public_key = generate_keypair()

        self.certificate = create_certificate(
            root_ca=root_ca,
            battery_id=battery_id,
            manufacturer_id=manufacturer_id,
            battery_public_key=serialize_public_key(self.public_key),
            issue_date="2026-01-01",
            expiry_date="2031-01-01",
        )

    def send_hello(self):

        return BatteryHello(certificate=self.certificate)

    def respond_to_challenge(self, challenge):

        challenge_data = challenge.nonce + str(challenge.timestamp).encode()

        signature = sign_message(self.private_key, challenge_data)

        return AuthResponse(signature=signature)
