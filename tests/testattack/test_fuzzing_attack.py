import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from can.encoder import encode_status
from can.status_message import BatteryStatus
from attacks.fuzzing_attack import FuzzingAttack


def main():
    fuzz = FuzzingAttack(seed=123)
    frames = fuzz.flood(count=10)
    assert len(frames) == 10

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
    corrupted = fuzz.corrupt_status_frame(original)
    assert corrupted.arbitration_id == original.arbitration_id

    print("Fuzzing attack test passed")


if __name__ == "__main__":
    main()
