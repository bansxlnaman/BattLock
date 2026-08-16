from can.can_message import CANMessage


class DelayAttack:
    """
    Timing / message-delay attack.

    The attacker holds messages in a buffer and releases them out of order
    or after an artificial delay.  This can break freshness assumptions,
    desynchronize authentication handshakes, or violate real-time safety
    guarantees.
    """

    def __init__(self):
        self.buffer = []

    def intercept(self, message):
        """Store a message instead of forwarding it."""
        self.buffer.append(message)
        print("DelayAttack buffered:", message)

    def release_all(self, reverse=False, drop_last=False):
        """
        Release buffered messages.

        Args:
            reverse: if True, release messages in reverse order.
            drop_last: if True, drop the last buffered message entirely
                       (combines delay with selective suspension).
        """
        if not self.buffer:
            return []

        messages = self.buffer[:]
        self.buffer.clear()

        if drop_last and messages:
            dropped = messages.pop()
            print("DelayAttack dropped last message:", dropped)

        if reverse:
            messages.reverse()
            print("DelayAttack releasing in REVERSE order")

        print(f"DelayAttack releasing {len(messages)} delayed messages")
        return messages

    def release_one(self):
        """Release the oldest buffered message."""
        if not self.buffer:
            return None
        msg = self.buffer.pop(0)
        print("DelayAttack released one:", msg)
        return msg

    def clear(self):
        """Drop all buffered messages (permanent denial)."""
        count = len(self.buffer)
        self.buffer.clear()
        print(f"DelayAttack cleared {count} messages")
