from can.encoder import (
    encode_battery_id,
    encode_status
)

from can.status_message import BatteryStatus

from crypto.counters.message_counter import MessageCounter
from can.encoder import encode_signature
from crypto.crypto_utils.signatures import sign_message
from can.decoder import (
    decode_nonce,
    decode_auth_result,
    decode_session_id
)
from can.encoder import encode_certificate


class BatteryNode:

    def __init__(self, battery):

        self.battery = battery

        # Crypto team's replay counter
        self.counter = MessageCounter()

    def send_identity(self):

        return encode_battery_id(
            self.battery
        )

    def send_status(self):

        status = BatteryStatus(

            # Counter increases every message
            counter=self.counter.next(),

            voltage=51.2,
            current=12.4,
            temperature=30.0,

            soc=85,
            soh=98,

            fault_flags=0
        )

        return encode_status(status)


    def receive_nonce(self, message):

        nonce = decode_nonce(message)

        print("Nonce Received:", nonce.hex())

        return nonce 
    
    def send_signature(
    self,
    private_key,
    nonce
):

        signature = sign_message(
        private_key,
        nonce
    )

        return encode_signature(
        signature
    )

    def send_signature(
    self,
    private_key,
    nonce
):

        signature = sign_message(
        private_key,
        nonce
    )

        return encode_signature(
        signature
    )

    def receive_auth_result(
    self,
    message
):

        result = decode_auth_result(
        message
    )

        print(
        "Authentication Result:",
        result
    )

        return result
    
    def receive_session_id(
    self,
    message
):

        session_id = decode_session_id(
        message
    )

        print(
        "Session ID:",
        session_id
    )

        return session_id
    
    def send_certificate(
    self,
    certificate
):

        return encode_certificate(
        certificate
    )


