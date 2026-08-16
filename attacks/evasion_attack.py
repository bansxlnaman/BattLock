from can.status_message import BatteryStatus
from can.encoder import encode_status


class EvasionAttack:
    """
    Adversarial / threshold evasion attack.

    Instead of injecting obviously out-of-range values (voltage=999,
    current=999), the attacker crafts telemetry that stays just below the
    vehicle's detection thresholds while still being unsafe or anomalous.
    This tests whether the system catches subtle attacks, not just blatant
    ones.
    """

    # Slightly below the thresholds used by VehicleNode
    VOLTAGE_LIMIT = 100.0
    CURRENT_LIMIT = 500.0
    TEMPERATURE_LIMIT = 150.0

    def inject_evasive_status(self,
                               voltage_factor=0.99,
                               current_factor=0.99,
                               temperature_factor=0.99,
                               counter=999):
        """
        Build a status frame with values just under the detection limits.

        The default counter=999 is intentionally stale so the replay guard
        will reject it.  Pass a fresh counter (e.g., from MessageCounter)
        to specifically demonstrate threshold-evasion detection.
        """
        status = BatteryStatus(
            counter=counter,
            voltage=self.VOLTAGE_LIMIT * voltage_factor,
            current=self.CURRENT_LIMIT * current_factor,
            temperature=self.TEMPERATURE_LIMIT * temperature_factor,
            soc=85,
            soh=98,
            fault_flags=0
        )

        print(
            "EvasionAttack injected values just below thresholds: "
            f"voltage={status.voltage}, current={status.current}, "
            f"temperature={status.temperature}"
        )

        return encode_status(status)

    def inject_fault_flag_evasion(self, fault_flags=0x01, counter=999):
        """
        Inject a status whose numeric fields are valid but whose fault_flags
        byte silently signals an overvoltage condition.  Tests whether the
        vehicle inspects fault_flags in addition to scalar thresholds.
        """
        status = BatteryStatus(
            counter=counter,
            voltage=51.2,
            current=12.4,
            temperature=30.0,
            soc=85,
            soh=98,
            fault_flags=fault_flags
        )

        print(
            "EvasionAttack injected valid scalars with fault_flags=",
            hex(fault_flags)
        )

        return encode_status(status)
