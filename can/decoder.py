import struct
import json
import base64

from can.status_message import BatteryStatus
from crypto.models.certificate_model import Certificate


def decode_battery_id(message):

    return message.data.decode()


def decode_status(message):

    counter, voltage, current, temperature, soc, soh, fault = \
        struct.unpack(
            "IfffBBB",
            message.data
        )

    return BatteryStatus(
        counter,

        voltage,
        current,
        temperature,

        soc,
        soh,

        fault
    )


def decode_nonce(message):

    return message.data


def decode_signature(message):

    return message.data


def decode_auth_result(message):

    return bool(message.data[0])


def decode_session_id(message):

    return message.data.decode()


def decode_certificate(message):
    """
    Deserialize a JSON CAN payload back into a proper Certificate object.
    Binary fields (public_key, signature) are base64-decoded from the JSON.
    This is the inverse of encode_certificate().
    """
    data = json.loads(message.data.decode())

    return Certificate(
        battery_id=data["battery_id"],
        manufacturer_id=data["manufacturer_id"],
        public_key=base64.b64decode(data["public_key"]),
        issue_date=data["issue_date"],
        expiry_date=data["expiry_date"],
        signature=base64.b64decode(data["signature"]),
    )


def decode_auth_request(message):

    return message.data.decode()