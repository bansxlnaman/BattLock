from cryptography.hazmat.primitives.asymmetric import ec


class RootCA:

    def __init__(self):

        self.private_key = ec.generate_private_key(ec.SECP256R1())

        self.public_key = self.private_key.public_key()
