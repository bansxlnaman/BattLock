from crypto.models.battery_identity import BatteryIdentity
from crypto.keys.key_manager import KeyManager


class Battery:

    def __init__(
        self,
        battery_id,
        serial_number,
        manufacturer_id
    ):

        self.identity = BatteryIdentity(
            battery_id=battery_id,
            serial_number=serial_number,
            manufacturer_id=manufacturer_id
        )

        self.keys = KeyManager()

        self.certificate = None

    def sign(self, data):

        return self.keys.sign(data)

    def get_public_key(self):

        return self.keys.get_public_key()