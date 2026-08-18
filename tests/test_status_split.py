"""
Unit tests for the Phase 3 status A/B/C split.

Runs with pytest, or standalone:  python tests/test_status_split.py

Proves:
  * BatteryStatus -> encode_status_a/b/c -> status_from_frames == original
  * each status frame is <= 8 bytes and carries the correct CAN ID
  * the aggregator returns a real BatteryStatus (attribute access works)

Note on floats: voltage/current/temperature are packed as 32-bit floats, so
they are compared with a small tolerance. counter/soc/soh/fault_flags are
integers and must match exactly. (The original encode_status used the same
32-bit float packing, so this is not new behavior.)
"""

import os
import sys
import struct

repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, repo_root)

from can.status_message import BatteryStatus
from can.encoder import encode_status_a, encode_status_b, encode_status_c
from can.decoder import (
    decode_status_a,
    decode_status_b,
    decode_status_c,
    status_from_frames,
)
from can.can_ids import (
    BATTERY_STATUS_A,
    BATTERY_STATUS_B,
    BATTERY_STATUS_C,
    OVERVOLTAGE,
    OVERTEMP,
)


def _f32(value):
    """Round-trip a Python float through 32-bit packing for comparison."""
    return struct.unpack("<f", struct.pack("<f", value))[0]


def _sample(counter=42, fault_flags=0):
    return BatteryStatus(
        counter=counter,
        voltage=51.2,
        current=12.4,
        temperature=30.0,
        soc=85,
        soh=98,
        fault_flags=fault_flags,
    )


def test_each_frame_within_8_bytes():
    s = _sample()
    for enc, arb in (
        (encode_status_a, BATTERY_STATUS_A),
        (encode_status_b, BATTERY_STATUS_B),
        (encode_status_c, BATTERY_STATUS_C),
    ):
        msg = enc(s)
        assert len(msg.data) <= 8, f"{enc.__name__} frame >8 bytes: {len(msg.data)}"
        assert msg.arbitration_id == arb


def test_roundtrip_aggregates_to_batterystatus():
    s = _sample(counter=1234, fault_flags=0)
    a, b, c = encode_status_a(s), encode_status_b(s), encode_status_c(s)
    result = status_from_frames(a, b, c)

    assert isinstance(result, BatteryStatus)
    # exact for integers
    assert result.counter == s.counter
    assert result.soc == s.soc
    assert result.soh == s.soh
    assert result.fault_flags == s.fault_flags
    # float32 tolerance for measurements
    assert result.voltage == _f32(s.voltage)
    assert result.current == _f32(s.current)
    assert result.temperature == _f32(s.temperature)


def test_attribute_access_still_works():
    # The whole point of the aggregator: vehicle_node reads these attributes.
    s = _sample()
    result = status_from_frames(
        encode_status_a(s), encode_status_b(s), encode_status_c(s)
    )
    _ = (result.counter, result.voltage, result.current, result.temperature)


def test_fault_flags_bitmask_preserved():
    s = _sample(fault_flags=OVERVOLTAGE | OVERTEMP)  # 0x0009
    a = encode_status_a(s)
    assert decode_status_a(a)["fault_flags"] == (OVERVOLTAGE | OVERTEMP)


def test_partial_decoders_return_expected_keys():
    s = _sample()
    assert set(decode_status_a(encode_status_a(s))) == {
        "counter", "soc", "soh", "fault_flags"
    }
    assert set(decode_status_b(encode_status_b(s))) == {"voltage", "current"}
    assert set(decode_status_c(encode_status_c(s))) == {"temperature"}


def test_counter_max_uint32():
    s = _sample(counter=4294967295)  # 0xFFFFFFFF, max uint32
    result = status_from_frames(
        encode_status_a(s), encode_status_b(s), encode_status_c(s)
    )
    assert result.counter == 4294967295


ALL_TESTS = [
    test_each_frame_within_8_bytes,
    test_roundtrip_aggregates_to_batterystatus,
    test_attribute_access_still_works,
    test_fault_flags_bitmask_preserved,
    test_partial_decoders_return_expected_keys,
    test_counter_max_uint32,
]


if __name__ == "__main__":
    passed = 0
    for t in ALL_TESTS:
        t()
        print(f"[PASS] {t.__name__}")
        passed += 1
    print(f"\n{passed}/{len(ALL_TESTS)} status-split tests passed")
