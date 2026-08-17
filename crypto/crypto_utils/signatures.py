from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)
from cryptography.exceptions import InvalidSignature

# ECDSA P-256 raw signature length: R (32 bytes) || S (32 bytes).
# This is the format the ATECC608A produces/consumes and the format
# carried on the CAN bus (BATTLOCK_SIG_LEN = 64 in battlock_protocol.h).
RAW_SIG_LEN = 64
CURVE_SCALAR_LEN = 32  # P-256


def generate_keypair():
    # Generate ECDSA keypair.

    private_key = ec.generate_private_key(ec.SECP256R1())

    public_key = private_key.public_key()

    return private_key, public_key


def sign_message(private_key, message: bytes) -> bytes:
    # Sign a message. Returns DER-encoded signature (~70-72 bytes).

    signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))

    return signature


def verify_signature(public_key, message: bytes, signature: bytes) -> bool:

    # Verify ECDSA signature. Accepts DER-encoded signatures.

    try:
        public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))

        return True

    except InvalidSignature:
        return False


# ---------------------------------------------------------------------
# DER <-> raw R||S conversion (hardware/CAN compatibility)
# ---------------------------------------------------------------------

def der_to_raw(der_signature: bytes) -> bytes:
    """
    Convert a DER-encoded ECDSA signature to raw R||S (64 bytes),
    matching the ATECC608A output and the CAN frame format.
    """
    r, s = decode_dss_signature(der_signature)
    return r.to_bytes(CURVE_SCALAR_LEN, "big") + s.to_bytes(CURVE_SCALAR_LEN, "big")


def raw_to_der(raw_signature: bytes) -> bytes:
    """
    Convert a raw R||S (64-byte) signature to DER encoding so the
    cryptography library can verify it.
    """
    if len(raw_signature) != RAW_SIG_LEN:
        raise ValueError(
            f"raw signature must be {RAW_SIG_LEN} bytes, got {len(raw_signature)}"
        )
    r = int.from_bytes(raw_signature[:CURVE_SCALAR_LEN], "big")
    s = int.from_bytes(raw_signature[CURVE_SCALAR_LEN:], "big")
    return encode_dss_signature(r, s)


def sign_message_raw(private_key, message: bytes) -> bytes:
    """Sign and return the raw 64-byte R||S signature."""
    return der_to_raw(sign_message(private_key, message))


def verify_signature_raw(public_key, message: bytes, raw_signature: bytes) -> bool:
    """Verify a raw 64-byte R||S signature (hardware/CAN format)."""
    try:
        der_signature = raw_to_der(raw_signature)
    except ValueError:
        return False
    return verify_signature(public_key, message, der_signature)
