from can.can_message import CANMessage
from can.can_ids import BATTERY_STATUS
from can.status_message import BatteryStatus
from can.encoder import encode_status
from can.decoder import decode_status


class MitMAttack:
    """
    Man-in-the-Middle attack on telemetry frames.

    The attacker intercepts a valid BATTERY_STATUS message, optionally
    modifies one or more fields while keeping the counter identical, and
    forwards the tampered frame.  Because the counter is unchanged, replay
    protection does not catch it; the vehicle must detect the modification
    cryptographically (signature) or through out-of-range checks.
    """

    def __init__(self):
        self.captured_message = None

    def intercept(self, message):
        """Capture a frame."""
        self.captured_message = message
        print("MITM intercepted:", message)

    def modify(self, voltage=None, current=None, temperature=None,
                soc=None, soh=None, fault_flags=None):
        """
        Decode the captured status, replace selected fields, and re-encode.
        Unspecified fields keep their original value.
        """
        if self.captured_message is None:
            raise RuntimeError("MITM: no message captured; call intercept() first")

        status = decode_status(self.captured_message)

        tampered = BatteryStatus(
            counter=status.counter,
            voltage=voltage if voltage is not None else status.voltage,
            current=current if current is not None else status.current,
            temperature=temperature if temperature is not None else status.temperature,
            soc=soc if soc is not None else status.soc,
            soh=soh if soh is not None else status.soh,
            fault_flags=fault_flags if fault_flags is not None else status.fault_flags,
        )

        print("MITM tampered status:", tampered)
        return encode_status(tampered)

    def forward(self, message):
        """Forward an arbitrary frame unchanged (eavesdropping mode)."""
        print("MITM forwarding:", message)
        return message
