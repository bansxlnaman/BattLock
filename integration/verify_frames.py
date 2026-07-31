"""Verify Simulink-generated CAN frames using the real BattLock code.

Reads the CAN frame stream exported by export_frames.m and applies the
actual BattLock verification functions to every frame:

    - ReplayProtection.validate()   (crypto/counters/replay_protection.py)
    - signature match               (model's documented keyed scheme)
    - voltage threshold             (mirrors Injection_Detection block)

Each verdict produced by Python is then compared against the flag the
Simulink model logged internally. Agreement between the independent
implementations is the integration evidence.

Usage:
    python verify_frames.py <frames.csv> <out.csv>
"""

import csv
import os
import sys

repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, repo_root)

from crypto.counters.replay_protection import ReplayProtection

# The Simulink model signs with: signature = nonce + 100  (Bias block).
# This mirrors the vehicle's EXPECTED computation inside Vehicle_Node.
SIGNATURE_BIAS = 100

# Voltage above this threshold is flagged as injection (matches the
# Injection_Detection relational operator threshold).
VOLTAGE_THRESHOLD = 100.0


def verify_frames(frames_path, out_path):
    rows = []
    with open(frames_path, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append(row)

    mode_results = {}
    out_rows = []
    for row in rows:
        mode = int(float(row["mode"]))
        replay = mode_results.setdefault(mode, ReplayProtection())
        if replay.last_counter == 0:
            # First time we see this mode: match the model Unit Delay
            # initial condition (-1) so the first frame is accepted.
            replay.last_counter = -1

        nonce = int(float(row["nonce"]))
        signature = int(float(row["signature"]))
        counter = int(float(row["counter"]))
        voltage = float(row["voltage"])

        expected = nonce + SIGNATURE_BIAS
        sig_ok = signature == expected

        replay_ok = replay.validate(counter)

        injection = voltage > VOLTAGE_THRESHOLD

        # Python's overall auth verdict for the frame.
        py_auth = 1 if sig_ok else 0

        out_rows.append({
            "mode": mode,
            "time": float(row["time"]),
            "py_signature_ok": 1 if sig_ok else 0,
            "py_replay": 0 if replay_ok else 1,
            "py_injection": 1 if injection else 0,
            "py_auth": py_auth,
            "model_auth": int(float(row["model_auth"])),
            "model_replay": int(float(row["model_replay"])),
            "model_injection": int(float(row["model_injection"])),
            "model_soc": float(row["model_soc"]),
        })

    # Write the per-frame comparison.
    fieldnames = out_rows[0].keys()
    with open(out_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(out_rows)

    # Per-mode agreement summary.
    print("\n=== PYTHON vs SIMULINK VERIFICATION AGREEMENT ===")
    print(f"{'mode':>4} {'desc':<22} {'py_auth':>7} {'mdl_auth':>8} "
          f"{'py_replay':>9} {'mdl_rep':>7} {'py_inj':>6} {'mdl_inj':>7} "
          f"{'agree':>6}")
    descriptions = {
        0: "No attack (baseline)",
        1: "Replay attack",
        2: "Signature spoofing",
        3: "Voltage injection",
        4: "Signature dropping",
        5: "Signature dropping",
    }
    for mode in sorted(mode_results):
        group = [r for r in out_rows if r["mode"] == mode]
        # A mode is "detected" if any frame raised the flag.
        py_auth = max(r["py_auth"] for r in group)
        mdl_auth = max(r["model_auth"] for r in group)
        py_replay = max(r["py_replay"] for r in group)
        mdl_replay = max(r["model_replay"] for r in group)
        py_inj = max(r["py_injection"] for r in group)
        mdl_inj = max(r["model_injection"] for r in group)
        agree = (
            py_auth == mdl_auth
            and py_replay == mdl_replay
            and py_inj == mdl_inj
        )
        print(f"{mode:>4} {descriptions[mode]:<22} {py_auth:>7} {mdl_auth:>8} "
              f"{py_replay:>9} {mdl_replay:>7} {py_inj:>6} {mdl_inj:>7} "
              f"{'YES' if agree else 'NO':>6}")

    print(f"\nWrote {len(out_rows)} verified frames to {out_path}")


if __name__ == "__main__":
    frames_path = sys.argv[1] if len(sys.argv) > 1 else "frames.csv"
    out_path = sys.argv[2] if len(sys.argv) > 2 else "frames_verified.csv"
    verify_frames(frames_path, out_path)
