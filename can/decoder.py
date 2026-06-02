import struct

from can.status_message import BatteryStatus



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

    return message.data.decode()

def decode_auth_request(message):

    return message.data.decode()