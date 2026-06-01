from cryptography.hazmat.primitives import serialization


def serialize_public_key(public_key) -> bytes:
    """
    Convert public key object to bytes.
    """

    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def deserialize_public_key(public_key_bytes: bytes):
    """
    Convert bytes back to public key object.
    """

    return serialization.load_pem_public_key(public_key_bytes)
