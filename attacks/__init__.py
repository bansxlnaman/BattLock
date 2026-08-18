"""
BattLock attack simulation modules.

Each module implements a specific adversarial action against the battery-
vehicle CAN bus.  The simulation runner in `can/simulation/run_simulation.py`
and the convenience script `run_attacks.py` exercise these attacks against
`VehicleNode` to demonstrate detection and mitigation.

Attacks currently implemented:
- replay_attack: re-injection of captured frames
- injection_attack: fabrication of out-of-range telemetry
- spoofing_attack: fake battery identity announcement
- dos_attack: bus flooding
- suspension_attack: message dropping
- mitm_attack: intercept-and-modify telemetry
- delay_attack: delay / reorder messages
- fuzzing_attack: random / malformed frames
- session_hijack_attack: replay captured session ID
- evasion_attack: values just below detection thresholds
- certificate_tampering_attack: expired, rogue, or tampered certificates
"""

from attacks.replay_attack import ReplayAttack
from attacks.injection_attack import InjectionAttack
from attacks.spoofing_attack import SpoofingAttack
from attacks.dos_attack import DoSAttack
from attacks.suspension_attack import SuspensionAttack
from attacks.mitm_attack import MitMAttack
from attacks.delay_attack import DelayAttack
from attacks.fuzzing_attack import FuzzingAttack
from attacks.session_hijack_attack import SessionHijackAttack
from attacks.evasion_attack import EvasionAttack
from attacks.certificate_tampering_attack import CertificateTamperingAttack

__all__ = [
    "ReplayAttack",
    "InjectionAttack",
    "SpoofingAttack",
    "DoSAttack",
    "SuspensionAttack",
    "MitMAttack",
    "DelayAttack",
    "FuzzingAttack",
    "SessionHijackAttack",
    "EvasionAttack",
    "CertificateTamperingAttack",
]
