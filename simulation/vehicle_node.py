from crypto.certs.certificate import verify_certificate

from crypto.auth.challenge import create_challenge

from crypto.auth.verifier import verify_challenge_response

from crypto.auth.session import create_session

from protocol.messages.auth_success import AuthSuccess


class VehicleNode:

    def __init__(self, manufacturer_public_key):

        self.manufacturer_public_key = manufacturer_public_key

        self.challenge = None

        self.certificate = None

    def process_hello(self, hello):

        self.certificate = hello.certificate

        return verify_certificate(self.certificate, self.manufacturer_public_key)

    def create_auth_challenge(self):

        self.challenge = create_challenge()

        return self.challenge

    def verify_auth_response(self, response):

        return verify_challenge_response(
            self.certificate, self.challenge, response.signature
        )

    def create_session(self):

        session = create_session(self.certificate.battery_id)

        return AuthSuccess(session_id=session.session_id)
