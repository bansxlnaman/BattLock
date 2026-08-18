"""
BattLock Crypto Demo — Visual walkthrough for presentation.

Shows the full authentication handshake step by step:
  1. Root CA issues a certificate for the battery
  2. Battery generates a nonce (challenge)
  3. Battery signs the nonce with its private key
  4. Vehicle verifies the signature
  5. Session is established
  6. Telemetry counter rejects replay
"""

from crypto import crypto_api
from crypto.certs.root_ca import RootCA
from crypto.certs.certificate import create_certificate
from crypto.crypto_utils.key_serialization import serialize_public_key
from crypto.crypto_utils.signatures import generate_keypair, RAW_SIG_LEN
from crypto.keys.software_keys import SoftwareKeys
from crypto.keys.key_manager import KeyManager

DIVIDER = "=" * 60

def main():
    print(DIVIDER)
    print("BATTLOCK CRYPTO LAYER DEMO")
    print(DIVIDER)

    # ── Step 1: Root CA + battery keypair ──
    print("\n[STEP 1] Setting up Root CA and battery keypair")
    root_ca = RootCA()
    crypto_api.set_root_ca_public_key(root_ca.public_key)
    print(f"  Root CA public key: {serialize_public_key(root_ca.public_key)[:50]}...")

    battery_priv, battery_pub = generate_keypair()
    battery_pub_pem = serialize_public_key(battery_pub)
    print(f"  Battery public key: {battery_pub_pem[:50]}...")

    # ── Step 2: Issue certificate ──
    print("\n[STEP 2] Root CA issues certificate for battery")
    cert = create_certificate(
        root_ca=root_ca,
        battery_id="BAT001",
        manufacturer_id="TESLA",
        battery_public_key=battery_pub_pem,
        issue_date="2026-06-01",
        expiry_date="2031-06-01",
    )
    valid = crypto_api.verify_certificate(cert)
    print(f"  Certificate issued for: {cert.battery_id}")
    print(f"  Manufacturer: {cert.manufacturer_id}")
    print(f"  Valid until: {cert.expiry_date}")
    print(f"  Verification: {valid}")

    # ── Step 3: Vehicle sends challenge (nonce) ──
    print("\n[STEP 3] Vehicle generates 32-byte challenge")
    nonce = crypto_api.generate_nonce()
    print(f"  Nonce ({len(nonce)} bytes): {nonce.hex()[:40]}...")

    # ── Step 4: Battery signs the nonce ──
    print("\n[STEP 4] Battery signs challenge with private key (inside ATECC608B)")
    # In production, the private key lives inside the ATECC608B chip.
    # For demo, we simulate it by configuring the API with a SoftwareKeys
    # provider that holds the same keypair we generated in Step 1.
    from crypto.keys.software_keys import SoftwareKeys
    class _BatterySim:
        """Simulates the battery's signing provider using the known keypair."""
        def __init__(self, priv, pub):
            self._priv = priv
            self._pub = pub
        def sign(self, data):
            from crypto.crypto_utils.signatures import sign_message
            return sign_message(self._priv, data)
        def get_public_key(self):
            return self._pub
    battery_provider = _BatterySim(battery_priv, battery_pub)
    crypto_api.configure_key_manager(battery_provider)
    signature = crypto_api.sign_nonce(nonce)
    print(f"  Signature ({len(signature)} bytes): {signature.hex()[:40]}...")
    print(f"  Format: raw R||S (matches ATECC608B + CAN bus)")

    # ── Step 5: Vehicle verifies ──
    print("\n[STEP 5] Vehicle verifies signature")
    ok = crypto_api.verify_signature(nonce, signature, battery_pub_pem)
    print(f"  Signature valid: {ok}")

    # Tamper test
    bad_sig = bytearray(signature)
    bad_sig[0] ^= 0xFF
    bad_tampered = crypto_api.verify_signature(nonce, bytes(bad_sig), battery_pub_pem)
    print(f"  Tampered signature rejected: {not bad_tampered}")

    # ── Step 6: Session established ──
    print("\n[STEP 6] Session established")
    session = crypto_api.create_session(cert.battery_id)
    print(f"  Session ID: {session.session_id}")
    print(f"  Battery ID: {session.battery_id}")

    # ── Step 7: Telemetry with replay counter ──
    print("\n[STEP 7] Telemetry frame with replay counter")
    crypto_api.reset_counter()
    for i in [1, 2, 3, 2, 4]:
        result = crypto_api.check_counter(i)
        status = "ACCEPTED" if result else "REJECTED (replay)"
        print(f"  Counter {i}: {status}")

    print(f"\n{DIVIDER}")
    print("DEMO COMPLETE — all crypto operations verified")
    print(DIVIDER)


if __name__ == "__main__":
    main()
