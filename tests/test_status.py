from can.status_message import BatteryStatus

from can.encoder import encode_status
from can.decoder import decode_status

import pytest


def test_status_roundtrip():

    status = BatteryStatus(
        counter=7,

        voltage=51.2,
        current=12.4,
        temperature=30.0,

        soc=85,
        soh=98,

        fault_flags=0
    )

    msg = encode_status(status)

    decoded = decode_status(msg)

    assert decoded.counter == 7
    assert decoded.voltage == pytest.approx(51.2)
    assert decoded.current == pytest.approx(12.4)
    assert decoded.temperature == pytest.approx(30.0)
    assert decoded.soc == 85
    assert decoded.soh == 98
    assert decoded.fault_flags == 0

    print(
        "\n[PASS]"
        " BatteryStatus encode/decode round-trip"
    )


if __name__ == "__main__":

    test_status_roundtrip()
