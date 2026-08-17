"""
Integration-contract test for the BattLock crypto API.

Verifies all six operations the Crypto/Security Lead must deliver, plus the
raw<->DER signature round-trip that ATECC608A/CAN compatibility depends on.
"""

from crypto import crypto_api
from crypto.certs.root_ca import RootCA
from crypto.certs.certificate import create_certificate
from crypto.crypto_utils.signatures import (
    generate_keypair,
    sign_message,
    der_to_raw,
    raw_to_der,
    RAW_SIG_LEN,
)
from crypto.crypto_utils.key_serialization import serialize_public_key


def run_test():
    # ---- setup: CA + battery keypair + certificate ----
    root_ca = RootCA()
    crypto_api.set_root_ca_public_key(root_ca.public_key)

    priv, pub = generate_keypair()
    pub_bytes = serialize_public_key(pub)

    cert = create_certificate(
        root_ca=root_ca,
        battery_id="BAT001",
        manufacturer_id="TESLA",
        battery_public_key=pub_bytes,
        issue_date="2026-06-01",
        expiry_date="2031-06-01",
    )

    # ---- 1. certificate ----
    assert crypto_api.verify_certificate(cert) is True
    print("1. verify_certificate: True")

    # ---- 2. nonce (secure random, 32 bytes) ----
    nonce = crypto_api.generate_nonce()
    assert len(nonce) == 32
    assert nonce != crypto_api.generate_nonce()
    print("2. generate_nonce: 32 secure bytes")

    # ---- 3. sign -> raw 64-byte R||S ----
    # The API's default software key manager holds its own keypair;
    # verify against ITS public key.
    api_pub_bytes = crypto_api.get_public_key_bytes()
    raw_sig = crypto_api.sign_nonce(nonce)
    assert len(raw_sig) == RAW_SIG_LEN
    print(f"3. sign_nonce: raw signature = {len(raw_sig)} bytes")

    # ---- 4. verify (raw and DER paths) ----
    assert crypto_api.verify_signature(nonce, raw_sig, api_pub_bytes) is True
    assert crypto_api.verify_signature(nonce, b"\x00" * RAW_SIG_LEN, api_pub_bytes) is False
    der_sig = sign_message(priv, nonce)
    assert crypto_api.verify_signature(nonce, der_sig, pub_bytes) is True
    print("4. verify_signature: raw=True, DER=True, tampered=False")

    # ---- format round-trip: one signature, DER -> raw -> DER ----
    raw_from_der = der_to_raw(der_sig)
    assert len(raw_from_der) == RAW_SIG_LEN
    assert raw_to_der(raw_from_der) == der_sig
    assert crypto_api.verify_signature(nonce, raw_from_der, pub_bytes) is True
    print("   der<->raw round-trip: OK")

    # ---- 5. session ----
    session = crypto_api.create_session(cert.battery_id)
    assert session.session_id and session.battery_id == "BAT001"
    print(f"5. create_session: {session.session_id}")

    # ---- 6. replay counter ----
    crypto_api.reset_counter()
    assert crypto_api.check_counter(1) is True
    assert crypto_api.check_counter(2) is True
    assert crypto_api.check_counter(1) is False   # replay
    assert crypto_api.check_counter(2) is False   # duplicate
    assert crypto_api.check_counter(3) is True
    print("6. check_counter: fresh accepted, replay rejected")

    print("\nALL CRYPTO API TESTS PASSED")


if __name__ == "__main__":
    run_test()
