from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature

def generate_keypair():
    # Generate ECDSA keypair.

    private_key = ec.generate_private_key(
        ec.SECP256R1()
    )

    public_key = private_key.public_key()

    return private_key, public_key


def sign_message(
    private_key,
    message: bytes
) -> bytes:
    # Sign a message.

    signature = private_key.sign(
        message,
        ec.ECDSA(hashes.SHA256())
    )

    return signature


def verify_signature(
    public_key,
    message: bytes,
    signature: bytes
) -> bool:

    # Verify ECDSA signature.

    try:
        public_key.verify(
            signature,
            message,
            ec.ECDSA(hashes.SHA256())
        )

        return True

    except InvalidSignature:
        return False