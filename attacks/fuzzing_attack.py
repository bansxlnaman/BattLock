import random
import struct

from can.can_message import CANMessage


class FuzzingAttack:
    """
    Random / protocol fuzzing attack on the CAN bus.

    Generates frames with random arbitration IDs, random payload lengths,
    and random bytes.  Useful for testing decoder robustness and finding
    crash / parsing bugs in the vehicle node.
    """

    # Keep inside the 11-bit standard CAN ID range
    ID_MIN = 0x000
    ID_MAX = 0x7FF

    def __init__(self, seed=None):
        if seed is not None:
            random.seed(seed)

    def random_frame(self):
        """Generate a single random CAN frame."""
        arbitration_id = random.randint(self.ID_MIN, self.ID_MAX)
        length = random.randint(0, 8)
        data = bytes(random.randint(0, 255) for _ in range(length))
        return CANMessage(arbitration_id=arbitration_id, data=data)

    def flood(self, count=100):
        """Generate *count* random frames."""
        messages = [self.random_frame() for _ in range(count)]
        print(f"FuzzingAttack generated {count} random frames")
        return messages

    def corrupt_status_frame(self, original):
        """
        Take a valid BATTERY_STATUS frame and randomly flip / truncate /
        extend its payload to produce malformed data.  This tests decoder
        resilience.
        """
        data = bytearray(original.data)
        operation = random.choice(["flip", "truncate", "extend", "shuffle"])

        if operation == "flip" and data:
            idx = random.randrange(len(data))
            data[idx] ^= (1 << random.randint(0, 7))
        elif operation == "truncate":
            new_len = random.randint(0, max(0, len(data) - 1))
            data = data[:new_len]
        elif operation == "extend":
            extra = random.randint(1, 8)
            data.extend(random.randint(0, 255) for _ in range(extra))
            data = data[:8]
        elif operation == "shuffle" and len(data) > 1:
            random.shuffle(data)

        return CANMessage(arbitration_id=original.arbitration_id, data=bytes(data))
