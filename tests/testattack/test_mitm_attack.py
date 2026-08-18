import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from can.encoder import encode_status
from can.status_message import BatteryStatus
from attacks.mitm_attack import MitMAttack


def main():
    status = BatteryStatus(
        counter=1,
        voltage=51.2,
        current=12.4,
        temperature=30.0,
        soc=85,
        soh=98,
        fault_flags=0
    )
    original = encode_status(status)

    mitm = MitMAttack()
    mitm.intercept(original)

    tampered = mitm.modify(voltage=85.0)
    assert tampered.arbitration_id == original.arbitration_id
    print("MITM attack test passed")


if __name__ == "__main__":
    main()
