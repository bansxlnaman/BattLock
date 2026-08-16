import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from can.encoder import encode_status
from can.status_message import BatteryStatus
from attacks.delay_attack import DelayAttack


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
    msg = encode_status(status)

    delay = DelayAttack()
    delay.intercept(msg)

    released = delay.release_all()
    assert len(released) == 1
    assert released[0] == msg
    print("Delay attack test passed")


if __name__ == "__main__":
    main()
