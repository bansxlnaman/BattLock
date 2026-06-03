from can.can_message import CANMessage
from can.can_ids import AUTH_REQUEST


class SpoofingAttack:

    def create_fake_identity(self):

        fake_message = CANMessage(
            arbitration_id=AUTH_REQUEST,
            data=b"FAKE_BATTERY"
        )

        print("Spoofed Battery Identity Created")

        return fake_message