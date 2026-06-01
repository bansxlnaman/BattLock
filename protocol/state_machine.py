from enum import Enum


class ConnectionState(Enum):

    DISCONNECTED = 0

    HELLO_RECEIVED = 1

    CERT_VERIFIED = 2

    CHALLENGE_SENT = 3

    AUTHENTICATED = 4

    ACTIVE_SESSION = 5


class BattLockStateMachine:

    def __init__(self):

        self.state = ConnectionState.DISCONNECTED

    def get_state(self):

        return self.state

    def hello_received(self):

        if self.state == ConnectionState.DISCONNECTED:

            self.state = ConnectionState.HELLO_RECEIVED

            return True

        return False

    def certificate_verified(self):

        if self.state == ConnectionState.HELLO_RECEIVED:

            self.state = ConnectionState.CERT_VERIFIED

            return True

        return False

    def challenge_sent(self):

        if self.state == ConnectionState.CERT_VERIFIED:

            self.state = ConnectionState.CHALLENGE_SENT

            return True

        return False

    def authenticated(self):

        if self.state == ConnectionState.CHALLENGE_SENT:

            self.state = ConnectionState.AUTHENTICATED

            return True

        return False

    def session_established(self):

        if self.state == ConnectionState.AUTHENTICATED:

            self.state = ConnectionState.ACTIVE_SESSION

            return True

        return False

    def reset(self):

        self.state = ConnectionState.DISCONNECTED

    def telemetry_allowed(self):

        return self.state == ConnectionState.ACTIVE_SESSION
