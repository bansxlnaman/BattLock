import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from can.decoder import decode_status
from attacks.evasion_attack import EvasionAttack


def main():
    evasion = EvasionAttack()

    msg = evasion.inject_evasive_status()
    status = decode_status(msg)
    assert status.voltage < 100
    assert status.current < 500
    assert status.temperature < 150

    fault_msg = evasion.inject_fault_flag_evasion(fault_flags=0x01)
    fault_status = decode_status(fault_msg)
    assert fault_status.fault_flags == 0x01

    print("Evasion attack test passed")


if __name__ == "__main__":
    main()
