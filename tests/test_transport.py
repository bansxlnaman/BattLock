"""
Unit tests for the CAN transport / fragmentation layer (Person 3).

Runs with pytest, or standalone:  python tests/test_transport.py

Proves the core property:  original == reassemble(fragment(original))
for nonce (32B), signature (~64-72B), certificate (148-483B), and edge sizes,
and that every produced frame respects the Classic CAN 8-byte limit.
"""

import os
import sys
import secrets

repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, repo_root)

from can.transport import fragment, reassemble, CANBus
from can.can_ids import NONCE, SIGNATURE, CERTIFICATE, CAN_MAX_DATA


def _roundtrip(arb_id, payload):
    frames = fragment(arb_id, payload)
    for f in frames:
        assert len(f.data) <= CAN_MAX_DATA, \
            f"frame exceeds {CAN_MAX_DATA} bytes: {len(f.data)}"
        assert f.arbitration_id == arb_id
    assert reassemble(frames) == payload, "reassembled payload != original"
    return frames


def test_nonce_roundtrip():
    frames = _roundtrip(NONCE, secrets.token_bytes(32))
    assert len(frames) == 5, f"32-byte nonce should be 5 frames, got {len(frames)}"


def test_signature_roundtrip():
    for size in (64, 70, 71, 72):
        _roundtrip(SIGNATURE, secrets.token_bytes(size))


def test_certificate_roundtrip():
    for size in (148, 256, 483):
        _roundtrip(CERTIFICATE, secrets.token_bytes(size))


def test_edge_sizes():
    # 0, exactly one frame, boundary, just over a frame, exactly two frames.
    for size in (0, 1, 5, 6, 8):
        _roundtrip(NONCE, secrets.token_bytes(size))


def test_small_payload_single_frame():
    frames = fragment(NONCE, b"\x01\x02\x03")
    assert len(frames) == 1
    assert reassemble(frames) == b"\x01\x02\x03"


def test_out_of_order_reassembly():
    payload = secrets.token_bytes(72)
    frames = fragment(SIGNATURE, payload)
    assert reassemble(list(reversed(frames))) == payload


def test_reassemble_rejects_duplicate_sequence():
    frames = fragment(NONCE, secrets.token_bytes(20))
    # Duplicate frame 1's sequence onto a copy of frame 0's data slot.
    corrupted = frames[:2] + [frames[1]] + frames[2:]
    try:
        reassemble(corrupted)
        assert False, "expected ValueError for duplicate sequence number"
    except ValueError as e:
        assert "duplicate" in str(e).lower()


def test_reassemble_rejects_missing_sequence():
    frames = fragment(NONCE, secrets.token_bytes(20))
    missing = [frames[0], frames[2]]  # drop frame 1, leaving a gap
    try:
        reassemble(missing)
        assert False, "expected ValueError for missing sequence number"
    except ValueError as e:
        assert "missing" in str(e).lower() or "non-contiguous" in str(e).lower()


def test_reassemble_rejects_oversized_frame():
    frames = fragment(NONCE, secrets.token_bytes(10))
    from can.can_message import CANMessage
    frames[0] = CANMessage(NONCE, frames[0].data + b"\x00" * 5)  # >8 bytes
    try:
        reassemble(frames)
        assert False, "expected ValueError for oversized frame"
    except ValueError as e:
        assert "8-byte" in str(e) or "exceeds" in str(e).lower()


def test_reassemble_rejects_mixed_arbitration_id():
    frames = fragment(NONCE, secrets.token_bytes(20))
    from can.can_message import CANMessage
    frames[1] = CANMessage(SIGNATURE, frames[1].data)  # wrong ID mixed in
    try:
        reassemble(frames)
        assert False, "expected ValueError for inconsistent arbitration_id"
    except ValueError as e:
        assert "arbitration_id" in str(e).lower()


def test_canbus_fifo():
    bus = CANBus()
    assert bus.receive() is None
    bus.send("a")
    bus.send("b")
    assert bus.receive() == "a"
    assert bus.receive() == "b"
    assert bus.receive() is None


ALL_TESTS = [
    test_nonce_roundtrip,
    test_signature_roundtrip,
    test_certificate_roundtrip,
    test_edge_sizes,
    test_small_payload_single_frame,
    test_out_of_order_reassembly,
    test_reassemble_rejects_duplicate_sequence,
    test_reassemble_rejects_missing_sequence,
    test_reassemble_rejects_oversized_frame,
    test_reassemble_rejects_mixed_arbitration_id,
    test_canbus_fifo,
]


if __name__ == "__main__":
    passed = 0
    for t in ALL_TESTS:
        t()
        print(f"[PASS] {t.__name__}")
        passed += 1
    print(f"\n{passed}/{len(ALL_TESTS)} transport tests passed")