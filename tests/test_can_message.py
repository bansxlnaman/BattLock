from can.can_message import CANMessage

msg = CANMessage(
    arbitration_id=0x100,
    data=b"BAT001"
)

print(msg)
