"""
Integrated attack-simulation runner.

Demonstrates the BattLock protocol flow under a battery of attacks:
1. Baseline identity / status
2. Replay attack
3. Injection attack
4. Suspension attack
5. MITM / telemetry tampering
6. Delay attack
7. Fuzzing attack
8. Session hijacking attack
9. Evasion attack (below-threshold injection)
10. Certificate tampering (expired / rogue / field tampered)
11. DoS flood

Run with:
    PYTHONPATH=. python can/simulation/run_simulation.py
"""

from crypto.models.battery_identity import BatteryIdentity
from can.transport import CANBus
from can.simulation.battery_node import BatteryNode
from can.simulation.vehicle_node import VehicleNode
from can.can_message import CANMessage

from attacks.replay_attack import ReplayAttack
from attacks.injection_attack import InjectionAttack
from attacks.suspension_attack import SuspensionAttack
from attacks.mitm_attack import MitMAttack
from attacks.delay_attack import DelayAttack
from attacks.fuzzing_attack import FuzzingAttack
from attacks.session_hijack_attack import SessionHijackAttack
from attacks.evasion_attack import EvasionAttack
from attacks.certificate_tampering_attack import CertificateTamperingAttack
from attacks.dos_attack import DoSAttack

from crypto.crypto_utils.random_gen import generate_nonce
from crypto.crypto_utils.signatures import (
    generate_keypair,
    sign_message,
)
from crypto.crypto_utils.key_serialization import serialize_public_key
from crypto.auth.session import create_session
from crypto.certs.root_ca import RootCA
from crypto.certs.certificate import create_certificate
from can.can_ids import NONCE, AUTH_RESULT, SESSION_ID, SIGNATURE


def _receive_vehicle(bus, vehicle_node):
    """Pop a frame from the bus and hand it to the vehicle node."""
    vehicle_node.receive(bus.receive())


def _receive_battery(bus, battery_node):
    """Pop a frame from the bus and hand it to the battery node."""
    # BatteryNode has receive_nonce(), receive_auth_result(),
    # receive_session_id().  We dispatch by CAN ID.
    msg = bus.receive()
    if msg.arbitration_id == NONCE:
        battery_node.receive_nonce(msg)
    elif msg.arbitration_id == AUTH_RESULT:
        battery_node.receive_auth_result(msg)
    elif msg.arbitration_id == SESSION_ID:
        battery_node.receive_session_id(msg)
    else:
        print("BatteryNode: unhandled frame", msg)


def main():
    battery_private_key, battery_public_key = generate_keypair()

    root_ca = RootCA()

    certificate = create_certificate(
        root_ca=root_ca,
        battery_id="BAT001",
        manufacturer_id="TESLA",
        battery_public_key=serialize_public_key(battery_public_key),
        issue_date="2026-06-01",
        expiry_date="2031-06-01"
    )

    battery = BatteryIdentity(
        battery_id="BAT001",
        serial_number="SN001",
        manufacturer_id="TESLA"
    )

    bus = CANBus()

    battery_node = BatteryNode(battery, bus)
    vehicle_node = VehicleNode(
        bus,
        root_ca_public_key=root_ca.public_key
    )

    print("\n=== 1. Baseline identity/status ===")
    bus.send(battery_node.send_identity()); _receive_vehicle(bus, vehicle_node)
    bus.send(battery_node.send_status());   _receive_vehicle(bus, vehicle_node)

    print("\n=== 2. Replay attack ===")
    replay = ReplayAttack()
    valid_status = battery_node.send_status()
    replay.capture(valid_status)
    bus.send(valid_status);                 _receive_vehicle(bus, vehicle_node)
    bus.send(replay.replay());              _receive_vehicle(bus, vehicle_node)

    print("\n=== 3. Injection attack ===")
    injection = InjectionAttack()
    bus.send(injection.inject_fake_status()); _receive_vehicle(bus, vehicle_node)

    print("\n=== 4. Suspension attack ===")
    suspension = SuspensionAttack()
    blocked = suspension.block(battery_node.send_status())
    if blocked is None:
        print("MESSAGE SUSPENDED")
    else:
        bus.send(blocked); _receive_vehicle(bus, vehicle_node)

    print("\n=== 5. MITM attack (modify voltage) ===")
    mitm = MitMAttack()
    captured = battery_node.send_status()
    mitm.intercept(captured)
    bus.send(mitm.modify(voltage=85.0));    _receive_vehicle(bus, vehicle_node)

    print("\n=== 6. Delay attack (reverse order) ===")
    delay = DelayAttack()
    m1 = battery_node.send_status()
    m2 = battery_node.send_status()
    delay.intercept(m1)
    delay.intercept(m2)
    for delayed in delay.release_all(reverse=True):
        bus.send(delayed)
        _receive_vehicle(bus, vehicle_node)

    print("\n=== 7. Fuzzing attack ===")
    fuzz = FuzzingAttack(seed=42)
    for frame in fuzz.flood(count=5):
        bus.send(frame)
        _receive_vehicle(bus, vehicle_node)
    corrupted = fuzz.corrupt_status_frame(battery_node.send_status())
    bus.send(corrupted); _receive_vehicle(bus, vehicle_node)

    print("\n=== 8. Authentication + session hijacking ===")
    cert_msg = battery_node.send_certificate(certificate)
    bus.send(cert_msg)
    vehicle_node.receive_and_verify_certificate(bus.receive())

    nonce = generate_nonce()
    nonce_msg = vehicle_node.send_nonce(nonce)
    bus.send(nonce_msg)
    _receive_battery(bus, battery_node)

    # Battery signs the same challenge bytes it received.
    challenge = battery_node._stored_challenge_data
    signature = sign_message(battery_private_key, challenge)
    sig_msg = CANMessage(arbitration_id=SIGNATURE, data=signature)
    bus.send(sig_msg)
    vehicle_node.receive_and_verify_signature(bus.receive())

    bus.send(vehicle_node.send_auth_result(True))
    _receive_battery(bus, battery_node)

    session = create_session(battery.battery_id)
    session_msg = vehicle_node.send_session_id(session)
    bus.send(session_msg)
    _receive_battery(bus, battery_node)

    hijack = SessionHijackAttack()
    hijack.capture(session_msg)
    bus.send(hijack.replay())
    _receive_vehicle(bus, vehicle_node)

    print("\n=== 9. Evasion attack ===")
    evasion = EvasionAttack()
    # Reset replay state so this demo shows the threshold/fault-flag
    # evasion detection path rather than the replay path.
    vehicle_node.replay.last_counter = 0
    bus.send(evasion.inject_evasive_status(counter=1))
    _receive_vehicle(bus, vehicle_node)
    bus.send(evasion.inject_fault_flag_evasion(counter=2))
    _receive_vehicle(bus, vehicle_node)

    print("\n=== 10. Certificate tampering attacks ===")
    tamper = CertificateTamperingAttack()

    expired_cert = tamper.create_expired_certificate(
        root_ca,
        public_key=serialize_public_key(battery_public_key)
    )
    bus.send(battery_node.send_certificate(expired_cert))
    vehicle_node.receive_and_verify_certificate(bus.receive())

    rogue_cert = tamper.create_self_signed_certificate(
        public_key=serialize_public_key(battery_public_key)
    )
    bus.send(battery_node.send_certificate(rogue_cert))
    vehicle_node.receive_and_verify_certificate(bus.receive())

    tampered_cert = create_certificate(
        root_ca=root_ca,
        battery_id="BAT001",
        manufacturer_id="TESLA",
        battery_public_key=serialize_public_key(battery_public_key),
        issue_date="2026-06-01",
        expiry_date="2031-06-01"
    )
    tamper.tamper_certificate_field(tampered_cert, "battery_id", "BAT_EVIL")
    bus.send(battery_node.send_certificate(tampered_cert))
    vehicle_node.receive_and_verify_certificate(bus.receive())

    print("\n=== 11. DoS flood ===")
    dos = DoSAttack()
    for msg in dos.flood(50):
        bus.send(msg)
    print("DoS messages queued:", len(bus.queue))

    print("\n=== Simulation complete ===")


if __name__ == "__main__":
    main()
