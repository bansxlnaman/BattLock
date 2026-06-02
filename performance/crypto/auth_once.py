from crypto.certs.root_ca import RootCA

from simulation.battery_node import BatteryNode
from simulation.vehicle_node import VehicleNode


def authenticate_once():

    root_ca = RootCA()

    battery = BatteryNode(
        battery_id="BAT001", manufacturer_id="THAPAR", root_ca=root_ca
    )

    vehicle = VehicleNode(root_ca.public_key)

    hello = battery.send_hello()

    if not vehicle.process_hello(hello):
        return False

    challenge = vehicle.create_auth_challenge()

    response = battery.respond_to_challenge(challenge)

    if not vehicle.verify_auth_response(response):
        return False

    vehicle.create_session()

    return True
