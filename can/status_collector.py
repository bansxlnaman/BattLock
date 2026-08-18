"""
BattLock CAN status-frame collector (Person 3 — CAN Protocol / Software).

Battery telemetry is transmitted as three separate Classic-CAN frames
(0x200 STATUS_A, 0x201 STATUS_B, 0x202 STATUS_C). A receiver cannot act on
any single frame alone -- it must collect all three of one round and then
aggregate them into a BatteryStatus before running replay / injection /
telemetry logic.

This collector buffers incoming status frames and emits a complete
BatteryStatus only when a full A -> B -> C round has arrived.

Round / missing-frame policy (must be mirrored on the ESP32 side):
  * STATUS_A (0x200) carries the counter and BEGINS a telemetry round.
    Receiving a STATUS_A always starts a fresh round, discarding any
    incomplete partial round still buffered.
  * STATUS_B / STATUS_C are only accepted while a round is open (i.e. after
    a STATUS_A has been seen). Orphan B/C frames with no open round are
    ignored.
  * A BatteryStatus is emitted (and the buffer cleared) only when A, B and
    C are all present.
  * If B or C is lost, the next STATUS_A discards the incomplete round --
    that telemetry sample is simply dropped, which is the safe behavior.

The collector performs no cryptography and no replay/injection checks; it
only reassembles telemetry. Those checks belong in the node layer that
consumes the emitted BatteryStatus.
"""

from can.can_ids import (
    BATTERY_STATUS_A,
    BATTERY_STATUS_B,
    BATTERY_STATUS_C,
)
from can.decoder import status_from_frames


class StatusCollector:

    def __init__(self):
        self._a = None
        self._b = None
        self._c = None

    def reset(self):
        self._a = None
        self._b = None
        self._c = None

    @property
    def pending(self):
        """True while a round is open (STATUS_A seen) but not yet complete."""
        return self._a is not None and (self._b is None or self._c is None)

    def feed(self, message):
        """Feed one CAN frame into the collector.

        Returns a complete BatteryStatus when this frame completes an
        A -> B -> C round, otherwise None. Non-status frames are ignored.
        """
        arb = message.arbitration_id

        if arb == BATTERY_STATUS_A:
            # A new round always starts here; drop any incomplete partial.
            self._a = message
            self._b = None
            self._c = None
        elif arb == BATTERY_STATUS_B:
            if self._a is not None:
                self._b = message
        elif arb == BATTERY_STATUS_C:
            if self._a is not None:
                self._c = message
        else:
            # Not a status frame -- collector leaves any open round untouched.
            return None

        if self._a is not None and self._b is not None and self._c is not None:
            status = status_from_frames(self._a, self._b, self._c)
            self.reset()
            return status

        return None
