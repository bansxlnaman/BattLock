from can.status_message import BatteryStatus

from can.encoder import encode_status
from can.decoder import decode_status


status = BatteryStatus(
    voltage=51.2,
    current=12.4,
    temperature=30.0,
    soc=85,
    soh=98,
    fault_flags=0
)

msg = encode_status(status)

decoded = decode_status(msg)

print(decoded)