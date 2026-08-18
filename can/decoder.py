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


# ----------------------------------------------------------------------------
# Status A/B/C split (Phase 3).
#
# Each frame carries only PART of a BatteryStatus, so the per-frame decoders
# honestly return partial dicts. status_from_frames() is the aggregator that
# recombines the three frames into a complete BatteryStatus object -- the same
# type the existing vehicle/replay/injection logic already expects (attribute
# access: status.counter, status.voltage, ...).
# ----------------------------------------------------------------------------

def decode_status_a(message):
    """Decode 0x200 -> {counter, soc, soh, fault_flags}."""
    counter, soc, soh, fault_flags, _reserved = struct.unpack(
        "<IBBBB",
        message.data
    )
    return {
        "counter": counter,
        "soc": soc,
        "soh": soh,
        "fault_flags": fault_flags,
    }


def decode_status_b(message):
    """Decode 0x201 -> {voltage, current}."""
    voltage, current = struct.unpack("<ff", message.data)
    return {
        "voltage": voltage,
        "current": current,
    }


def decode_status_c(message):
    """Decode 0x202 -> {temperature} (ignores the 4 reserved bytes)."""
    temperature = struct.unpack("<f", message.data[:4])[0]
    return {
        "temperature": temperature,
    }


def status_from_frames(status_a, status_b, status_c):
    """Aggregate the three status frames into one BatteryStatus object.

    Accepts the three CANMessages (0x200, 0x201, 0x202) and returns a
    BatteryStatus with the same attributes the simulation already reads.
    """
    a = decode_status_a(status_a)
    b = decode_status_b(status_b)
    c = decode_status_c(status_c)

    return BatteryStatus(
        counter=a["counter"],
        voltage=b["voltage"],
        current=b["current"],
        temperature=c["temperature"],
        soc=a["soc"],
        soh=a["soh"],
        fault_flags=a["fault_flags"],
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