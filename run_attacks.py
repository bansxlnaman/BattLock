#!/usr/bin/env python3
"""
Convenience runner for all BattLock attack simulations.

Usage:
    python run_attacks.py

This executes the integrated simulation plus each standalone attack test.
"""

import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent
TESTS = REPO / "tests" / "testattack"
SIM = REPO / "can" / "simulation" / "run_simulation.py"

scripts = [
    SIM,
    TESTS / "test_replay_attack.py",
    TESTS / "test_injection_attack.py",
    TESTS / "test_suspension_attack.py",
    TESTS / "test_dos_attack.py",
    TESTS / "test_mitm_attack.py",
    TESTS / "test_delay_attack.py",
    TESTS / "test_fuzzing_attack.py",
    TESTS / "test_session_hijack_attack.py",
    TESTS / "test_evasion_attack.py",
    TESTS / "test_certificate_tampering_attack.py",
]


def main():
    env = dict(**subprocess.os.environ)
    env["PYTHONPATH"] = str(REPO)

    failures = []
    for script in scripts:
        print(f"\n{'='*60}")
        print(f"Running {script.relative_to(REPO)}")
        print("=" * 60)
        result = subprocess.run(
            [sys.executable, str(script)],
            cwd=REPO,
            env=env,
        )
        if result.returncode != 0:
            failures.append(str(script.relative_to(REPO)))

    print("\n" + "=" * 60)
    if failures:
        print("FAILED:")
        for f in failures:
            print(f"  - {f}")
        sys.exit(1)
    else:
        print("All attack simulations completed successfully.")


if __name__ == "__main__":
    main()
