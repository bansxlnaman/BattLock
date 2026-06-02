from can.encoder import (
    encode_battery_id,
    encode_status,
    encode_signature,
    encode_certificate,
)

from can.status_message import BatteryStatus

from crypto.counters.message_counter import MessageCounter
from can.decoder import (
    decode_nonce,
    decode_auth_result,
    decode_session_id
)


class BatteryNode:

    def __init__(self, battery, bus):

        self.battery = battery
        self.bus = bus
        self.counter = MessageCounter()

        # Stores the raw challenge bytes received from the vehicle so that
        # sign_and_respond() can sign exactly the same byte sequence.
        self._stored_challenge_data = None

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
        """
        Decode the challenge bytes from a NONCE CAN frame and store them.
        The vehicle sends nonce + str(timestamp) combined, so these bytes
        are exactly what must be signed.
        """
        challenge_data = decode_nonce(message)
        self._stored_challenge_data = challenge_data

        print("Challenge Received via CAN:", challenge_data.hex())

        return challenge_data

    def sign_and_respond(self):
        """
        Sign the stored challenge data using the battery's private key and
        return an encoded SIGNATURE CAN message ready to be placed on the bus.

        The orchestrator must NEVER call battery.sign() directly.
        All signing goes through this method so that the full path is:
          BatteryNode.sign_and_respond()
          → battery.sign()              (private key stays inside battery)
          → encode_signature()
          → CANMessage(SIGNATURE, ...)  (returned to caller for bus.send)
        """
        if self._stored_challenge_data is None:
            raise RuntimeError(
                "BatteryNode.sign_and_respond(): no challenge data stored. "
                "Call receive_nonce() first."
            )

        signature = self.battery.sign(self._stored_challenge_data)

        print("Challenge Signed by BatteryNode")

        return encode_signature(signature)

    def receive_auth_result(self, message):

        result = decode_auth_result(message)

        print(
            "Authentication Result:",
            result
        )

        return result

    def receive_session_id(self, message):

        session_id = decode_session_id(message)

        print(
            "Session ID:",
            session_id
        )

        return session_id

    def send_certificate(self, certificate):

        return encode_certificate(certificate)

    def sign_challenge(self, challenge_data):
        """
        Low-level helper kept for test compatibility.
        Prefer sign_and_respond() in the integrated flow.
        """
        return self.battery.sign(challenge_data)
