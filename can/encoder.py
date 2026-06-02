import struct
import json
import base64

from can.can_message import CANMessage
from can.can_ids import (
    AUTH_REQUEST,
    BATTERY_STATUS,
    NONCE,
    SIGNATURE,
    AUTH_RESULT
)
from can.can_ids import SESSION_ID
from can.can_ids import CERTIFICATE


def encode_battery_id(battery):

    return CANMessage(
        arbitration_id=AUTH_REQUEST,
        data=battery.battery_id.encode()
    )


def encode_status(status):

    payload = struct.pack(
        "IfffBBB",
        status.counter,

        status.voltage,
        status.current,
        status.temperature,

        status.soc,
        status.soh,
        status.fault_flags
    )

    return CANMessage(
        arbitration_id=BATTERY_STATUS,
        data=payload
    )


def encode_nonce(nonce):

    return CANMessage(
        arbitration_id=NONCE,
        data=nonce
    )


def encode_signature(signature):

    return CANMessage(
        arbitration_id=SIGNATURE,
        data=signature
    )


def encode_auth_result(result):

    return CANMessage(
        arbitration_id=AUTH_RESULT,
        data=bytes([int(result)])
    )


def encode_session_id(session):

    return CANMessage(
        arbitration_id=SESSION_ID,
        data=session.session_id.encode()
    )


def encode_certificate(certificate):
    """
    Serialize a Certificate to a structured JSON CAN payload.
    Binary fields (public_key, signature) are base64-encoded so they
    survive the UTF-8 JSON round-trip cleanly.
    decode_certificate() reconstructs a proper Certificate object.
    """
    payload = json.dumps({
        "battery_id":      certificate.battery_id,
        "manufacturer_id": certificate.manufacturer_id,
        "public_key":      base64.b64encode(certificate.public_key).decode(),
        "issue_date":      certificate.issue_date,
        "expiry_date":     certificate.expiry_date,
        "signature":       base64.b64encode(certificate.signature).decode(),
    }).encode()

    return CANMessage(
        arbitration_id=CERTIFICATE,
        data=payload
    )


def encode_auth_request():

    return CANMessage(
        arbitration_id=AUTH_REQUEST,
        data=b"AUTH"
    )