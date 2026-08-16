# Attack Simulations

This directory contains the adversarial models used to demonstrate BattLock's
security properties.  Each module is a self-contained attack class; together
they are exercised by `can/simulation/run_simulation.py` and the convenience
runner `run_attacks.py`.

## Attack inventory

| File | Attack | What it demonstrates |
|------|--------|---------------------|
| `replay_attack.py` | Replay | Re-injecting a captured frame is rejected by the replay counter. |
| `injection_attack.py` | Data injection | Out-of-range telemetry triggers the injection detector. |
| `spoofing_attack.py` | Identity spoofing | A fake `AUTH_REQUEST` is rejected by certificate/signature verification. |
| `dos_attack.py` | Denial of service | Flooding the bus with high-priority frames. |
| `suspension_attack.py` | Message suspension | Dropping / withholding messages. |
| `mitm_attack.py` | Man-in-the-middle | Intercepting and modifying telemetry; the unchanged counter makes it a replay. |
| `delay_attack.py` | Delay / reorder | Buffering and releasing frames late or out of order. |
| `fuzzing_attack.py` | Fuzzing | Random CAN IDs and payloads test decoder resilience. |
| `session_hijack_attack.py` | Session hijacking | Replaying a captured `SESSION_ID` frame. |
| `evasion_attack.py` | Threshold evasion | Values just below detection limits, plus hidden `fault_flags`. |
| `certificate_tampering_attack.py` | Cert tampering | Expired, self-signed/rogue, and field-tampered certificates. |

## Running the simulations

```powershell
# Run everything (integrated + standalone tests)
python run_attacks.py

# Run only the integrated simulation
PYTHONPATH=. python can/simulation/run_simulation.py

# Run a single attack test
PYTHONPATH=. python tests/testattack/test_mitm_attack.py
```

## Adding a new attack

1. Create `attacks/<name>_attack.py` with a `CamelCaseAttack` class.
2. Return a `CANMessage`, a list of messages, or `None` for drop-style attacks.
3. Add detection logic in `can/simulation/vehicle_node.py` if applicable.
4. Add a test in `tests/testattack/test_<name>_attack.py`.
5. Import and exercise it in `can/simulation/run_simulation.py`.
6. Add it to `attacks/__init__.py` and this README.
