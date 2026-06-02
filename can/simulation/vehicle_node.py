from can.decoder import (
    decode_battery_id,
    decode_status,
    decode_signature
)

from crypto.counters.replay_protection import ReplayProtection

from can.encoder import (
    encode_nonce,
    encode_auth_result,
    encode_session_id
)
from can.decoder import decode_certificate

from can.encoder import encode_auth_request


class VehicleNode:

    def __init__(self, bus):
        self.bus = bus
        self.replay = ReplayProtection()

    def receive(self, message):

        if message.arbitration_id == 0x100:

            battery_id = decode_battery_id(message)

            print("Received:", battery_id)

        elif message.arbitration_id == 0x200:

            status = decode_status(message)

            if self.replay.validate(status.counter):

                if (
                    status.voltage > 100 or
                    status.current > 500 or
                    status.temperature > 150
                ):

                    print("INJECTION ATTACK DETECTED")

                else:

                    print("VALID:", status)

            else:

                print("REPLAY ATTACK DETECTED")

    def send_nonce(self, nonce):

        return encode_nonce(
            nonce
        )

    def send_auth_request(self):

        return encode_auth_request()

    def receive_signature(self, message):

        signature = decode_signature(
            message
        )

        print("Signature Received")

        return signature

    def send_auth_result(self, result):

        return encode_auth_result(
            result
        )
    
    def send_session_id(
    self,
    session
):

        return encode_session_id(
        session
    )

    def receive_certificate(
    self,
    message
):

        certificate = decode_certificate(
        message
    )

        print(
        "Certificate Received"
    )

        return certificate