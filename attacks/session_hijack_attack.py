from can.can_message import CANMessage
from can.can_ids import SESSION_ID


class SessionHijackAttack:
    """
    Session hijacking attack.

    The attacker sniffs a valid SESSION_ID frame during authentication and
    later re-injects it to impersonate an already authorized battery.
    A well-designed system must bind the session ID to the authenticated
    identity and/or time window so the replayed session ID is rejected.
    """

    def __init__(self):
        self.captured_session = None

    def capture(self, message):
        """Sniff a SESSION_ID frame."""
        if message.arbitration_id != SESSION_ID:
            raise ValueError("SessionHijackAttack: expected SESSION_ID frame")
        self.captured_session = message
        print("Session hijacker captured:", message)

    def replay(self):
        """Re-inject the captured session ID."""
        if self.captured_session is None:
            raise RuntimeError("SessionHijackAttack: no session captured")
        print("Session hijacker replaying:", self.captured_session)
        return self.captured_session

    def create_fake_session(self, session_id="HACKED"):
        """Create a completely fabricated session ID frame."""
        msg = CANMessage(
            arbitration_id=SESSION_ID,
            data=session_id.encode()
        )
        print("Session hijacker created fake session:", msg)
        return msg
