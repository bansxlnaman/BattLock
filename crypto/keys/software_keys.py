from crypto.crypto_utils.signatures import generate_keypair, sign_message


class SoftwareKeys:

    def __init__(self):

        self.private_key, self.public_key = generate_keypair()

    def sign(self, data: bytes):

        return sign_message(self.private_key, data)

    def get_public_key(self):

        return self.public_key
