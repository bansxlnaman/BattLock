from dataclasses import dataclass


@dataclass
class Certificate:
    """
    BattLock Battery Certificate
    """

    battery_id: str
    manufacturer_id: str

    public_key: bytes

    issue_date: str
    expiry_date: str

    signature: bytes
