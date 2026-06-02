from dataclasses import dataclass


@dataclass
class CANMessage:
    arbitration_id: int
    data: bytes