from crypto.models.battery_identity import BatteryIdentity
from can.transport import CANBus
from can.simulation.battery_node import BatteryNode
from can.simulation.vehicle_node import VehicleNode
from can.attacks.replay_attack import ReplayAttack
from can.attacks.injection_attack import InjectionAttack
from can.attacks.suspension_attack import SuspensionAttack
from can.attacks.dos_attack import DoSAttack
from crypto.crypto_utils.random_gen import generate_nonce
from crypto.crypto_utils.signatures import generate_keypair
battery_private_key, battery_public_key = generate_keypair()
from crypto.auth.session import create_session
from crypto.certs.root_ca import RootCA

from crypto.certs.certificate import (
    create_certificate
)

from crypto.crypto_utils.key_serialization import (
    serialize_public_key
)

root_ca = RootCA()

certificate = create_certificate(
    root_ca=root_ca,
    battery_id="BAT001",
    manufacturer_id="TESLA",
    battery_public_key=serialize_public_key(
        battery_public_key
    ),
    issue_date="2026-06-01",
    expiry_date="2031-06-01"
)



battery = BatteryIdentity(
    battery_id="BAT001",
    serial_number="SN001",
    manufacturer_id="TESLA"
)

bus = CANBus()

battery_node = BatteryNode(battery)

vehicle_node = VehicleNode()

# -------------------------
# Identity Message Test
# -------------------------

identity_msg = battery_node.send_identity()

bus.send(identity_msg)

vehicle_node.receive(
    bus.receive()
)

# -------------------------
# Status Message Test
# -------------------------

status_msg = battery_node.send_status()

bus.send(status_msg)

vehicle_node.receive(
    bus.receive()
)
# -------------------------
# Identity Test
# -------------------------

identity_msg = battery_node.send_identity()

bus.send(identity_msg)

vehicle_node.receive(
    bus.receive()
)

# -------------------------
# Valid Status Test
# -------------------------

attack = ReplayAttack()

valid_msg = battery_node.send_status()

attack.capture(valid_msg)

bus.send(valid_msg)

vehicle_node.receive(
    bus.receive()
)

# -------------------------
# Replay Attack Test
# -------------------------

replayed_msg = attack.replay()

bus.send(replayed_msg)

vehicle_node.receive(
    bus.receive()
)
attack = InjectionAttack()

fake_msg = attack.inject_fake_status()

bus.send(fake_msg)

vehicle_node.receive(
    bus.receive()
)
# -------------------------
# Suspension Attack Test
# -------------------------

suspension = SuspensionAttack()

msg = battery_node.send_status()

blocked_msg = suspension.block(msg)

if blocked_msg is not None:

    bus.send(blocked_msg)

    vehicle_node.receive(
        bus.receive()
    )

else:

    print("MESSAGE SUSPENDED")
    

certificate_msg = battery_node.send_certificate(
    certificate
)

bus.send(certificate_msg)

vehicle_node.receive_certificate(
    bus.receive()
)


# -------------------------
# Authentication Flow
# -------------------------

nonce = generate_nonce()

nonce_msg = vehicle_node.send_nonce(
    nonce
)

bus.send(nonce_msg)

battery_node.receive_nonce(
    bus.receive()
)


signature_msg = battery_node.send_signature(
    battery_private_key,
    nonce
)

bus.send(signature_msg)

vehicle_node.receive_signature(
    bus.receive()
)


auth_msg = vehicle_node.send_auth_result(
    True
)

bus.send(auth_msg)

battery_node.receive_auth_result(
    bus.receive()
)


session = create_session(
    battery.battery_id
)

session_msg = vehicle_node.send_session_id(
    session
)

bus.send(session_msg)

battery_node.receive_session_id(
    bus.receive()
)


# -------------------------
# DoS Attack Test
# -------------------------

dos = DoSAttack()

spam_messages = dos.flood(100)

for msg in spam_messages:

    bus.send(msg)

print(
    "DoS Flood Messages:",
    len(spam_messages)
)

print(
    "Queue Length:",
    len(bus.queue)
)


