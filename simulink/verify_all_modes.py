"""
Unified verification pipeline for Simulink + Python attack modes.

Reads simulink/frames.csv (modes 0-5 from Simulink) and
simulink/frames_extra.csv (modes 6-11 from Python attack classes),
verifies every frame with real BattLock crypto code, and produces:
    - simulink/frames_verified_all.csv  (per-frame verdicts)
    - simulink/verification_report_all.csv (per-mode summary)

Run with:
    PYTHONPATH=. python simulink/verify_all_modes.py
"""

import csv
import os
import sys

repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, repo_root)

from crypto.counters.replay_protection import ReplayProtection

SIGNATURE_BIAS = 100
VOLTAGE_THRESHOLD = 100.0

DESCRIPTIONS = {
    0: "No attack (baseline)",
    1: "Replay attack",
    2: "Signature spoofing",
    3: "Voltage injection",
    4: "Signature dropping",
    5: "Spoof + voltage injection",
    6: "MITM telemetry tamper",
    7: "Delay / reorder",
    8: "Fuzzing",
    9: "Session hijacking",
    10: "Threshold evasion",
    11: "Certificate tampering",
}


def _read_csv(path):
    rows = []
    with open(path, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append(row)
    return rows


def verify_all(frames_csv, extra_csv, out_csv, report_csv):
    all_rows = _read_csv(frames_csv) + _read_csv(extra_csv)

    mode_results = {}
    out_rows = []

    for row in all_rows:
        mode = int(float(row["mode"]))
        replay = mode_results.setdefault(mode, ReplayProtection())
        if replay.last_counter == 0:
            replay.last_counter = -1

        nonce = int(float(row["nonce"]))
        signature = int(float(row["signature"]))
        counter = int(float(row["counter"]))
        voltage = float(row["voltage"])

        expected = nonce + SIGNATURE_BIAS
        sig_ok = signature == expected
        replay_ok = replay.validate(counter)
        injection = voltage > VOLTAGE_THRESHOLD

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

    fieldnames = out_rows[0].keys()
    with open(out_csv, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(out_rows)

    # Per-mode report
    with open(report_csv, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "mode", "description", "py_auth", "model_auth",
            "py_replay", "model_replay", "py_injection", "model_injection", "agreement"
        ])
        for mode in sorted(mode_results):
            group = [r for r in out_rows if r["mode"] == mode]
            py_auth = max(r["py_auth"] for r in group)
            mdl_auth = max(r["model_auth"] for r in group)
            py_rep = max(r["py_replay"] for r in group)
            mdl_rep = max(r["model_replay"] for r in group)
            py_inj = max(r["py_injection"] for r in group)
            mdl_inj = max(r["model_injection"] for r in group)
            agree = (
                py_auth == mdl_auth
                and py_rep == mdl_rep
                and py_inj == mdl_inj
            )
            writer.writerow([
                mode, DESCRIPTIONS[mode], py_auth, mdl_auth,
                py_rep, mdl_rep, py_inj, mdl_inj, "YES" if agree else "NO"
            ])

    print(f"Wrote {len(out_rows)} verified frames to {out_csv}")
    print(f"Wrote per-mode report to {report_csv}")


if __name__ == "__main__":
    simdir = os.path.join(repo_root, "simulink")
    verify_all(
        os.path.join(simdir, "frames.csv"),
        os.path.join(simdir, "frames_extra.csv"),
        os.path.join(simdir, "frames_verified_all.csv"),
        os.path.join(simdir, "verification_report_all.csv"),
    )
