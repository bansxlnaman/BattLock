from dataclasses import dataclass


@dataclass
class BatteryIdentity:
    """
    Unique identity of a battery pack.
    """

    battery_id: str
    serial_number: str
    manufacturer_id: str
