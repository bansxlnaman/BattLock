"""
BattLock hardware <-> software cross-compatibility test.

This is the proof that the Python crypto layer and the physical ATECC608B
chip are interchangeable:

    Test A: chip signs a fixed nonce, Python verifies it.
    Test B: Python signs the nonce, the chip verifies it.
    Test C: tampered signature is rejected by the chip.

Run after flashing hardware/atecc_bridge.ino on the battery ESP32 and
provisioning the chip (provision.py).

Usage:
    python provisioning/cross_compat_test.py --port COM5
"""

import argparse
import os
import sys

repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, repo_root)

from crypto.keys.atecc608 import ATECC608
from crypto import crypto_api
from crypto.crypto_utils.signatures import generate_keypair, sign_message_raw
from crypto.crypto_utils.key_serialization import serialize_public_key

# Deterministic challenge so both sides sign the exact same bytes.
TEST_NONCE = bytes(range(32))  # 0x00 0x01 ... 0x1F


def main():
    ap = argparse.ArgumentParser(description="BattLock HW/SW cross-compat test")
    ap.add_argument("--port", default="COM5", help="bridge serial port (battery ESP32)")
    args = ap.parse_args()

    print(f"Connecting to ATECC608B on {args.port} ...")
    chip = ATECC608(port=args.port)
    chip.connect()
    print("  connected\n")

    # ---- Test A: hardware signs, Python verifies ----
    print("[A] Chip signs nonce -> Python verifies")
    sig_hw = chip.sign(TEST_NONCE)
    pub_key = chip.get_public_key()
    pub_pem = serialize_public_key(pub_key)
    ok_a = crypto_api.verify_signature(TEST_NONCE, sig_hw, pub_pem)
    print(f"    hardware signature valid in Python: {ok_a}")
    assert ok_a, "Test A FAILED"

    # ---- Test B: Python signs, hardware verifies ----
    print("[B] Python signs nonce -> chip verifies")
    priv, pub = generate_keypair()
    sig_sw = sign_message_raw(priv, TEST_NONCE)          # raw 64-byte R||S
    pub_raw = _pubkey_to_raw(pub)
    resp = chip._query(
        "VERIFY " + TEST_NONCE.hex() + " " + sig_sw.hex() + " " + pub_raw.hex()
    )
    ok_b = resp == "VERIFY:1"
    print(f"    software signature valid on chip: {ok_b}  ({resp})")
    assert ok_b, "Test B FAILED"

    # ---- Test C: tampered signature rejected by chip ----
    print("[C] Tampered signature -> chip rejects")
    bad_sig = bytearray(sig_sw)
    bad_sig[0] ^= 0x01
    resp = chip._query(
        "VERIFY " + TEST_NONCE.hex() + " " + bytes(bad_sig).hex() + " " + pub_raw.hex()
    )
    ok_c = resp == "VERIFY:0"
    print(f"    tampered signature rejected on chip: {ok_c}  ({resp})")
    assert ok_c, "Test C FAILED"

    chip.close()
    print("\nCROSS-COMPATIBILITY VERIFIED — hardware and Python crypto agree.")


def _pubkey_to_raw(pub_key_obj) -> bytes:
    """Convert a cryptography public key to raw 64-byte X||Y."""
    nums = pub_key_obj.public_numbers()
    return (
        nums.x.to_bytes(32, "big") + nums.y.to_bytes(32, "big")
    )


if __name__ == "__main__":
    main()
