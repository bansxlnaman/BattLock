"""
Unit tests for the status-frame collector (Phase 4 prep, Person 3).

Runs with pytest, or standalone:  python tests/test_status_collector.py

Proves the collector emits a BatteryStatus only on a complete A->B->C round,
ignores orphan B/C frames, restarts cleanly on a new STATUS_A, handles
consecutive rounds, and is not disturbed by unrelated (non-status) frames.
"""

import os
import sys

repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, repo_root)

from can.status_message import BatteryStatus
from can.encoder import (
    encode_status_a,
    encode_status_b,
    encode_status_c,
    encode_nonce,
)
from can.status_collector import StatusCollector


def _frames(counter=1, voltage=51.2, current=12.4, temperature=30.0,
            soc=85, soh=98, fault=0):
    s = BatteryStatus(counter, voltage, current, temperature, soc, soh, fault)
    return encode_status_a(s), encode_status_b(s), encode_status_c(s)


def test_complete_round_emits_batterystatus():
    a, b, c = _frames(counter=7, soc=80)
    col = StatusCollector()
    assert col.feed(a) is None
    assert col.feed(b) is None
    result = col.feed(c)
    assert isinstance(result, BatteryStatus)
    assert result.counter == 7
    assert result.soc == 80


def test_partial_round_returns_none_then_completes():
    a, b, c = _frames()
    col = StatusCollector()
    assert col.feed(a) is None
    assert col.pending is True
    assert col.feed(b) is None
    assert col.pending is True
    assert col.feed(c) is not None
    assert col.pending is False


def test_orphan_b_c_ignored_without_a():
    a, b, c = _frames()
    col = StatusCollector()
    assert col.feed(b) is None
    assert col.feed(c) is None
    assert col.pending is False          # no round was ever opened
    # a proper round afterwards still works
    assert col.feed(a) is None
    assert col.feed(b) is None
    assert col.feed(c) is not None


def test_new_a_resets_incomplete_round():
    a1, b1, _ = _frames(counter=1)
    a2, b2, c2 = _frames(counter=2)
    col = StatusCollector()
    col.feed(a1)
    col.feed(b1)                          # round 1 incomplete (C1 lost)
    col.feed(a2)                          # new A drops round 1, starts round 2
    col.feed(b2)
    result = col.feed(c2)
    assert result is not None
    assert result.counter == 2


def test_consecutive_rounds_emit_twice():
    col = StatusCollector()
    a1, b1, c1 = _frames(counter=1)
    a2, b2, c2 = _frames(counter=2)
    col.feed(a1)
    col.feed(b1)
    r1 = col.feed(c1)
    col.feed(a2)
    col.feed(b2)
    r2 = col.feed(c2)
    assert r1.counter == 1
    assert r2.counter == 2


def test_non_status_frame_does_not_disturb_open_round():
    a, b, c = _frames(counter=5)
    col = StatusCollector()
    col.feed(a)
    # a stray nonce frame mid-round must be ignored, round stays open
    assert col.feed(encode_nonce(b"\x00" * 32)) is None
    assert col.pending is True
    col.feed(b)
    result = col.feed(c)
    assert result is not None
    assert result.counter == 5


ALL_TESTS = [
    test_complete_round_emits_batterystatus,
    test_partial_round_returns_none_then_completes,
    test_orphan_b_c_ignored_without_a,
    test_new_a_resets_incomplete_round,
    test_consecutive_rounds_emit_twice,
    test_non_status_frame_does_not_disturb_open_round,
]


if __name__ == "__main__":
    passed = 0
    for t in ALL_TESTS:
        t()
        print(f"[PASS] {t.__name__}")
        passed += 1
    print(f"\n{passed}/{len(ALL_TESTS)} status-collector tests passed")
