from crypto.certs.root_ca import RootCA

from simulation.network import Network
from simulation.battery_node import BatteryNode
from simulation.vehicle_node import VehicleNode


def run_test():

    print(
        "\n=== BattLock Full Authentication ===\n"
    )

    root_ca = RootCA()

    network = Network()

    battery = BatteryNode(
        battery_id="BAT001",
        manufacturer_id="THAPAR",
        root_ca=root_ca
    )

    vehicle = VehicleNode(
        root_ca.public_key
    )

    hello = network.send(
        "Battery",
        "Vehicle",
        battery.send_hello()
    )

    cert_valid = (
        vehicle.process_hello(
            hello
        )
    )

    print(
        "Certificate Valid:",
        cert_valid
    )

    if not cert_valid:
        return

    challenge = network.send(
        "Vehicle",
        "Battery",
        vehicle.create_auth_challenge()
    )

    response = network.send(
        "Battery",
        "Vehicle",
        battery.respond_to_challenge(
            challenge
        )
    )

    auth_valid = (
        vehicle.verify_auth_response(
            response
        )
    )

    print(
        "Authentication Valid:",
        auth_valid
    )

    if not auth_valid:
        return

    success = network.send(
        "Vehicle",
        "Battery",
        vehicle.create_session()
    )

    print(
        "Session ID:",
        success.session_id
    )

    print(
        "\nAuthentication Successful"
    )


if __name__ == "__main__":
    run_test()