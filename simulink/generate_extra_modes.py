"""
Generate CAN-frame-like rows for attack modes 6-11 using the real BattLock
Python attack classes.  The output schema matches simulink/frames.csv so it
can be concatenated with Simulink-produced modes 0-5 and fed through the
same verification pipeline.

Columns: mode,time,nonce,signature,counter,voltage,model_state,model_auth,
         model_replay,model_injection,model_soc

Modes:
    6 MITM (telemetry tamper)
    7 Delay / timing
    8 Fuzzing
    9 Session hijacking
   10 Evasion (threshold + fault flag)
   11 Certificate tampering
"""

import csv
import os
import sys
import struct

repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, repo_root)

from can.status_message import BatteryStatus
from can.encoder import encode_status, encode_battery_id, encode_certificate
from can.decoder import decode_status
from can.can_message import CANMessage
from can.can_ids import BATTERY_STATUS, AUTH_REQUEST, SESSION_ID, CERTIFICATE
from can.simulation.battery_node import BatteryNode
from can.simulation.vehicle_node import VehicleNode
from can.transport import CANBus

from attacks.mitm_attack import MitMAttack
from attacks.delay_attack import DelayAttack
from attacks.fuzzing_attack import FuzzingAttack
from attacks.session_hijack_attack import SessionHijackAttack
from attacks.evasion_attack import EvasionAttack
from attacks.certificate_tampering_attack import CertificateTamperingAttack
from attacks.dos_attack import DoSAttack

from crypto.models.battery_identity import BatteryIdentity
from crypto.certs.root_ca import RootCA
from crypto.certs.certificate import create_certificate, verify_certificate
from crypto.crypto_utils.signatures import generate_keypair, sign_message
from crypto.crypto_utils.key_serialization import serialize_public_key
from crypto.crypto_utils.random_gen import generate_nonce
from crypto.auth.session import create_session
from crypto.counters.replay_protection import ReplayProtection

SIGNATURE_BIAS = 100
VOLTAGE_THRESHOLD = 100.0


def _status_to_row(mode, time_, nonce, signature, status, model_state,
                   model_auth, model_replay, model_injection, model_soc,
                   cert_ok=1, session_ok=1, malformed=0):
    """Build a frames.csv-style row dict from a BatteryStatus.

    cert_ok / session_ok / malformed are attack-type hints the verifier
    uses to emit the py_cert_ok / py_session_ok / py_malformed verdicts.
    """
    return {
        "mode": mode,
        "time": round(time_, 6),
        "nonce": nonce,
        "signature": signature,
        "counter": status.counter,
        "voltage": status.voltage,
        "model_state": model_state,
        "model_auth": model_auth,
        "model_replay": model_replay,
        "model_injection": model_injection,
        "model_soc": model_soc,
        "cert_ok": cert_ok,
        "session_ok": session_ok,
        "malformed": malformed,
    }


def _battery_and_cert():
    """Create a fresh battery identity + valid certificate."""
    battery_private_key, battery_public_key = generate_keypair()
    root_ca = RootCA()
    battery = BatteryIdentity(
        battery_id="BAT001",
        serial_number="SN001",
        manufacturer_id="TESLA"
    )
    certificate = create_certificate(
        root_ca=root_ca,
        battery_id="BAT001",
        manufacturer_id="TESLA",
        battery_public_key=serialize_public_key(battery_public_key),
        issue_date="2026-06-01",
        expiry_date="2031-06-01"
    )
    return battery, battery_private_key, battery_public_key, root_ca, certificate


def mode_6_mitm():
    """MITM: valid counter but voltage/current pushed into evasion zone."""
    battery, *_ = _battery_and_cert()
    bus = CANBus()
    battery_node = BatteryNode(battery, bus)
    vehicle = VehicleNode(bus)

    rows = []
    t = 0.0
    valid = battery_node.send_status()
    vehicle.receive(valid)  # register counter
    rows.append(_status_to_row(6, t, 0, 0, decode_status(valid), 5, 1, 0, 0, 85))

    mitm = MitMAttack()
    mitm.intercept(valid)
    tampered = mitm.modify(voltage=97.0, current=480.0)
    t += 0.1
    rows.append(_status_to_row(6, t, 0, 0, decode_status(tampered), 5, 1, 0, 1, 0))
    return rows


def mode_7_delay():
    """Delay attack: two valid frames released out of order."""
    battery, *_ = _battery_and_cert()
    bus = CANBus()
    battery_node = BatteryNode(battery, bus)
    vehicle = VehicleNode(bus)

    rows = []
    m1 = battery_node.send_status()
    m2 = battery_node.send_status()

    delay = DelayAttack()
    delay.intercept(m1)
    delay.intercept(m2)

    t = 0.0
    for delayed in delay.release_all(reverse=True):
        vehicle.receive(delayed)
        status = decode_status(delayed)
        replay = 1 if not vehicle.replay.validate(status.counter) else 0
        rows.append(_status_to_row(7, t, 0, 0, status, 5, 1, replay, 0, 85 if replay == 0 else 0))
        t += 0.1
    return rows


def mode_8_fuzzing():
    """Fuzzing attack: random frames + one corrupted status frame."""
    battery, *_ = _battery_and_cert()
    bus = CANBus()
    battery_node = BatteryNode(battery, bus)
    vehicle = VehicleNode(bus)

    fuzz = FuzzingAttack(seed=42)
    rows = []
    t = 0.0
    for frame in fuzz.flood(count=3):
        vehicle.receive(frame)
        rows.append({
            "mode": 8,
            "time": round(t, 6),
            "nonce": 0,
            "signature": 0,
            "counter": 0,
            "voltage": 0.0,
            "model_state": 0,
            "model_auth": 0,
            "model_replay": 0,
            "model_injection": 0,
            "model_soc": 0,
        })
        t += 0.05

    valid = battery_node.send_status()
    corrupted = fuzz.corrupt_status_frame(valid)
    vehicle.receive(corrupted)
    rows.append({
        "mode": 8,
        "time": round(t, 6),
        "nonce": 0,
        "signature": 0,
        "counter": 0,
        "voltage": 0.0,
        "model_state": 5,
        "model_auth": 0,
        "model_replay": 0,
        "model_injection": 1,
        "model_soc": 0,
        "cert_ok": 1,
        "session_ok": 1,
        "malformed": 1,
    })
    return rows


def mode_9_session_hijack():
    """Session hijacking: replay captured SESSION_ID."""
    battery, priv, pub, root_ca, cert = _battery_and_cert()
    bus = CANBus()
    battery_node = BatteryNode(battery, bus)
    vehicle = VehicleNode(bus, root_ca_public_key=root_ca.public_key)

    rows = []
    t = 0.0

    # Normal auth flow
    vehicle.receive_and_verify_certificate(
        battery_node.send_certificate(cert)
    )
    nonce = generate_nonce()
    challenge = nonce
    vehicle.send_nonce(challenge)
    battery_node.receive_nonce(CANMessage(arbitration_id=0x101, data=challenge))
    sig = sign_message(priv, challenge)
    vehicle.receive_and_verify_signature(CANMessage(arbitration_id=0x102, data=sig))

    session = create_session(battery.battery_id)
    session_msg = vehicle.send_session_id(session)
    battery_node.receive_session_id(session_msg)

    rows.append({
        "mode": 9, "time": round(t, 6),
        "nonce": 0, "signature": 0, "counter": 0, "voltage": 0.0,
        "model_state": 5, "model_auth": 1, "model_replay": 0,
        "model_injection": 0, "model_soc": 85,
    })
    t += 0.1

    # Hijacker replays session ID
    hijack = SessionHijackAttack()
    hijack.capture(session_msg)
    replayed = hijack.replay()
    vehicle.receive(replayed)
    rows.append({
        "mode": 9, "time": round(t, 6),
        "nonce": 0, "signature": 0, "counter": 0, "voltage": 0.0,
        "model_state": 5, "model_auth": 1, "model_replay": 1,
        "model_injection": 0, "model_soc": 0,
        "cert_ok": 1, "session_ok": 0, "malformed": 0,
    })
    return rows


def mode_10_evasion():
    """Evasion: values just below thresholds + hidden fault flags."""
    battery, *_ = _battery_and_cert()
    bus = CANBus()
    battery_node = BatteryNode(battery, bus)
    vehicle = VehicleNode(bus)

    rows = []
    evasion = EvasionAttack()

    vehicle.replay.last_counter = 0
    msg1 = evasion.inject_evasive_status(counter=1)
    vehicle.receive(msg1)
    rows.append(_status_to_row(10, 0.0, 0, 0, decode_status(msg1), 5, 1, 0, 1, 0))

    msg2 = evasion.inject_fault_flag_evasion(counter=2)
    vehicle.receive(msg2)
    rows.append(_status_to_row(10, 0.1, 0, 0, decode_status(msg2), 5, 1, 0, 1, 0))
    return rows


def mode_11_certificate_tampering():
    """Certificate tampering: expired, rogue, and tampered certificates."""
    battery, priv, pub, root_ca, valid_cert = _battery_and_cert()
    bus = CANBus()
    battery_node = BatteryNode(battery, bus)
    vehicle = VehicleNode(bus, root_ca_public_key=root_ca.public_key)

    tamper = CertificateTamperingAttack()
    pub_bytes = serialize_public_key(pub)

    rows = []
    t = 0.0
    for label, cert in [
        ("expired", tamper.create_expired_certificate(root_ca, public_key=pub_bytes)),
        ("rogue", tamper.create_self_signed_certificate(public_key=pub_bytes)),
        ("tampered", tamper.tamper_certificate_field(valid_cert, "battery_id", "BAT_EVIL")),
    ]:
        ok = verify_certificate(cert, root_ca.public_key)
        vehicle.receive_and_verify_certificate(battery_node.send_certificate(cert))
        rows.append({
            "mode": 11, "time": round(t, 6),
            "nonce": 0, "signature": 0, "counter": 0, "voltage": 0.0,
            "model_state": 2, "model_auth": 1 if ok else 0, "model_replay": 0,
            "model_injection": 0, "model_soc": 0,
            "cert_ok": 1 if ok else 0, "session_ok": 1, "malformed": 0,
        })
        t += 0.1
    return rows


def generate_extra_modes(out_path):
    rows = []
    rows.extend(mode_6_mitm())
    rows.extend(mode_7_delay())
    rows.extend(mode_8_fuzzing())
    rows.extend(mode_9_session_hijack())
    rows.extend(mode_10_evasion())
    rows.extend(mode_11_certificate_tampering())

    fieldnames = [
        "mode", "time", "nonce", "signature", "counter", "voltage",
        "model_state", "model_auth", "model_replay", "model_injection", "model_soc",
        "cert_ok", "session_ok", "malformed"
    ]
    with open(out_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"Wrote {len(rows)} rows for modes 6-11 to {out_path}")


if __name__ == "__main__":
    default = os.path.join(repo_root, "simulink", "frames_extra.csv")
    out = sys.argv[1] if len(sys.argv) > 1 else default
    generate_extra_modes(out)
