"""
BattLock ATECC608B provisioning tool.

Run ONCE per battery chip.  Requires hardware/atecc_bridge.ino flashed
on the battery ESP32 and connected to the laptop over USB.

What it does:
    1. Connects to the chip via serial bridge.
    2. Creates the battery private key in slot 0 (never leaves the chip).
    3. Reads the public key back.
    4. Issues a Root-CA-signed certificate and saves all artifacts.

Usage:
    python provisioning/provision.py --port COM5
    python provisioning/provision.py --port COM5 --skip-genkey   # key exists
"""

import argparse
import base64
import json
import os
import sys
from datetime import datetime, timedelta

repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, repo_root)

from crypto.keys.atecc608 import ATECC608
from crypto.certs.root_ca import RootCA
from crypto.certs.certificate import create_certificate, verify_certificate
from crypto.crypto_utils.key_serialization import serialize_public_key
from cryptography.hazmat.primitives import serialization

OUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "out")


def _write(path, data: bytes):
    with open(path, "wb") as f:
        f.write(data)
    print(f"  wrote {path}")


def provision(port, battery_id, manufacturer_id, skip_genkey):
    os.makedirs(OUT_DIR, exist_ok=True)

    # ---- connect ----
    print(f"[1/5] Connecting to ATECC608B on {port} ...")
    chip = ATECC608(port=port)
    chip.connect()
    print("  chip responded (PING -> PONG)")

    # ---- generate key (or skip) ----
    if not skip_genkey:
        print("[2/5] Creating battery private key in slot 0 ...")
        chip.genkey()
        print("  keypair created — private key is locked inside the chip")
    else:
        print("[2/5] --skip-genkey: using existing slot-0 key")

    # ---- read public key ----
    print("[3/5] Reading battery public key ...")
    pub_key_obj = chip.get_public_key()
    pub_pem = serialize_public_key(pub_key_obj)
    _write(os.path.join(OUT_DIR, "battery_public_key.pem"), pub_pem)

    # ---- issue certificate ----
    print("[4/5] Issuing certificate (Root CA signs) ...")
    root_ca = RootCA()
    issue = datetime.utcnow().strftime("%Y-%m-%d")
    expiry = (datetime.utcnow() + timedelta(days=365 * 5)).strftime("%Y-%m-%d")
    cert = create_certificate(
        root_ca=root_ca,
        battery_id=battery_id,
        manufacturer_id=manufacturer_id,
        battery_public_key=pub_pem,
        issue_date=issue,
        expiry_date=expiry,
    )

    # self-check: the cert we just issued must verify
    ok = verify_certificate(cert, root_ca.public_key)
    if not ok:
        raise RuntimeError("self-check failed: freshly issued cert does not verify")
    print("  certificate issued and self-verified")

    # ---- save artifacts ----
    print("[5/5] Saving artifacts ...")
    cert_json = {
        "battery_id": cert.battery_id,
        "manufacturer_id": cert.manufacturer_id,
        "public_key_pem": pub_pem.decode(),
        "issue_date": cert.issue_date,
        "expiry_date": cert.expiry_date,
        "signature_b64": base64.b64encode(cert.signature).decode(),
    }
    with open(os.path.join(OUT_DIR, "battery_certificate.json"), "w") as f:
        json.dump(cert_json, f, indent=2)
    print(f"  wrote {os.path.join(OUT_DIR, 'battery_certificate.json')}")

    _write(
        os.path.join(OUT_DIR, "root_ca_public_key.pem"),
        serialize_public_key(root_ca.public_key),
    )
    _write(
        os.path.join(OUT_DIR, "root_ca_private_key.pem"),
        root_ca.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ),
    )

    chip.close()
    print("\nPROVISIONING COMPLETE")
    print(f"Artifacts in: {OUT_DIR}")
    print("Next: flash battery.ino, then run cross_compat_test.py")


def main():
    ap = argparse.ArgumentParser(description="BattLock ATECC608B provisioning")
    ap.add_argument("--port", default="COM3",
                    help="bridge serial port (battery ESP32)")
    ap.add_argument("--battery-id", default="BAT001")
    ap.add_argument("--manufacturer", default="TESLA")
    ap.add_argument("--skip-genkey", action="store_true",
                    help="do not create a new key (use existing slot-0 key)")
    args = ap.parse_args()
    provision(args.port, args.battery_id, args.manufacturer, args.skip_genkey)


if __name__ == "__main__":
    main()
