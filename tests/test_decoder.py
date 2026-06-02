from can.can_message import CANMessage
from can.decoder import decode_battery_id

msg = CANMessage(
    arbitration_id=0x100,
    data=b"BAT001"
)

print(decode_battery_id(msg))