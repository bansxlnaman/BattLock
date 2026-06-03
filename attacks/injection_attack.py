from can.status_message import BatteryStatus
from can.encoder import encode_status


class InjectionAttack:

    def inject_fake_status(self):

        fake_status = BatteryStatus(
            counter=999,

            voltage=999.0,
            current=999.0,
            temperature=999.0,

            soc=100,
            soh=100,

            fault_flags=0
        )

        return encode_status(fake_status)