import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from can.can_message import CANMessage
from can.can_ids import SESSION_ID
from attacks.session_hijack_attack import SessionHijackAttack


def main():
    session = CANMessage(arbitration_id=SESSION_ID, data=b"SESSION_42")

    hijack = SessionHijackAttack()
    hijack.capture(session)

    replayed = hijack.replay()
    assert replayed == session

    fake = hijack.create_fake_session("FAKE")
    assert fake.arbitration_id == SESSION_ID

    print("Session hijack attack test passed")


if __name__ == "__main__":
    main()
