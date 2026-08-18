"""
BattLock Cryptographic API  (integration contract)
==================================================

This is the ONLY module the integration layer (firmware glue, CAN nodes,
demo scripts) should call. It exposes exactly the six operations the
Crypto/Security Lead is responsible for:

    generate_nonce()                                -> bytes (32)
    sign_nonce(nonce)                               -> bytes (raw 64-byte R||S)
    verify_signature(nonce, signature, pubkey_bytes)-> bool
    verify_certificate(certificate)                 -> bool
    create_session(battery_id)                      -> Session
    check_counter(counter)                          -> bool

Design notes
------------
* Signature format: the CAN bus and the ATECC608A both use the raw
  64-byte R||S form (see crypto_utils/signatures.py). ``sign_nonce``
  returns raw and ``verify_signature`` accepts raw (or legacy DER).
* ``verify_certificate`` and ``check_counter`` are stateful — configure the
  trusted Root CA once with ``set_root_ca_public_key`` and the replay
  window resets via ``reset_counter``.
* Signing uses a KeyManager. Software keys are the default so the Python
  simulation mirrors the firmware; pass ``KeyManager(use_hardware=True)``
  to ``sign_nonce``/``configure_key_manager`` to use the ATECC608A.

Do NOT import crypto internals elsewhere — call this module.
"""

from crypto.crypto_utils.random_gen import generate_nonce as _generate_nonce
from crypto.crypto_utils.key_serialization import (
    serialize_public_key,
    deserialize_public_key,
)
from crypto.crypto_utils.signatures import (
    der_to_raw,
    verify_signature as _verify_der,
    verify_signature_raw as _verify_raw,
    RAW_SIG_LEN,
)
from crypto.keys.key_manager import KeyManager
from crypto.certs.certificate import verify_certificate as _verify_certificate
from crypto.auth.session import create_session as _create_session, Session
from crypto.counters.replay_protection import ReplayProtection


# ---------------------------------------------------------------------
# Module state (configured once by the integration layer)
# ---------------------------------------------------------------------

_key_manager = None            # signing provider (software by default)
_root_ca_public_key = None     # trusted CA key for certificate checks
_replay = ReplayProtection()   # replay/freshness window


def configure_key_manager(key_manager):
    """Set the signing provider (e.g. KeyManager(use_hardware=True))."""
    global _key_manager
    _key_manager = key_manager


def set_root_ca_public_key(public_key):
    """Register the trusted Root CA public key (key object or PEM bytes)."""
    global _root_ca_public_key
    if isinstance(public_key, (bytes, bytearray)):
        public_key = deserialize_public_key(bytes(public_key))
    _root_ca_public_key = public_key


def _get_key_manager():
    global _key_manager
    if _key_manager is None:
        _key_manager = KeyManager(use_hardware=False)
    return _key_manager


# ---------------------------------------------------------------------
# 2. Nonce — secure random 32-byte challenge
# ---------------------------------------------------------------------

def generate_nonce(length: int = 32) -> bytes:
    return _generate_nonce(length)


# ---------------------------------------------------------------------
# 3. ECDSA sign — private key -> sign(nonce) -> 64-byte signature
# ---------------------------------------------------------------------

def sign_nonce(nonce: bytes, key_manager=None) -> bytes:
    """
    Sign a nonce/challenge and return the raw 64-byte R||S signature
    (the exact bytes that travel on the CAN bus).

    SoftwareKeys returns DER (~70 B); ATECC608B returns raw R||S (64 B).
    Both are normalized to raw here so the CAN format is always the same.
    """
    km = key_manager or _get_key_manager()
    sig = km.sign(nonce)
    if len(sig) == RAW_SIG_LEN:
        return sig          # hardware path — already raw
    return der_to_raw(sig)  # software path — DER → raw


def get_public_key_bytes(key_manager=None) -> bytes:
    """PEM-serialized public key of the active signing provider."""
    km = key_manager or _get_key_manager()
    return serialize_public_key(km.get_public_key())


# ---------------------------------------------------------------------
# 4. Verification — signature + nonce + battery public key -> bool
# ---------------------------------------------------------------------

def verify_signature(nonce: bytes, signature: bytes, public_key_bytes: bytes) -> bool:
    """
    Verify an ECDSA signature over a nonce against a PEM-encoded public key.
    Accepts raw 64-byte R||S (hardware/CAN) or DER-encoded signatures.
    """
    public_key = deserialize_public_key(public_key_bytes)
    if len(signature) == RAW_SIG_LEN:
        return _verify_raw(public_key, nonce, signature)
    return _verify_der(public_key, nonce, signature)


# ---------------------------------------------------------------------
# 1. Certificate — verify against the trusted Root CA
# ---------------------------------------------------------------------

def verify_certificate(certificate) -> bool:
    if _root_ca_public_key is None:
        raise RuntimeError(
            "crypto_api.verify_certificate: no Root CA key configured. "
            "Call set_root_ca_public_key() first."
        )
    return _verify_certificate(certificate, _root_ca_public_key)


# ---------------------------------------------------------------------
# 5. Session establishment
# ---------------------------------------------------------------------

def create_session(battery_id) -> Session:
    return _create_session(battery_id)


# ---------------------------------------------------------------------
# 6. Replay counter — freshness of telemetry frames
# ---------------------------------------------------------------------

def check_counter(counter: int) -> bool:
    """True if counter is fresh (strictly increasing), False if replayed/stale."""
    return _replay.validate(counter)


def reset_counter():
    """Reset the replay window (e.g. on a new authenticated session)."""
    global _replay
    _replay = ReplayProtection()
