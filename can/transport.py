"""
BattLock CAN transport layer (Person 3 — CAN Protocol / Software).

Two responsibilities live here:

  1. CANBus              the in-memory bus used by the software simulation.
  2. fragment/reassemble a BattLock-specific multi-frame protocol that splits
                         payloads larger than 8 bytes (nonce, signature,
                         certificate) into Classic-CAN frames and rebuilds
                         them losslessly on the receiving side.

Fragmentation contract (also written up in docs/can_transport_contract.md):

  First frame  (sequence 0):
      byte 0      sequence number (0)
      byte 1      total payload length, low byte
      byte 2      total payload length, high byte
      bytes 3..7  up to 5 payload bytes

  Continuation frames (sequence 1, 2, ... N):
      byte 0      sequence number
      bytes 1..7  up to 7 payload bytes

Rules:
  * Every frame is <= 8 bytes (Classic CAN).
  * All frames of one payload share the same arbitration_id.
  * The total length lives in the first frame, so the receiver knows it is
    finished by byte count. No separate end-of-message flag is needed.
  * Sequence is one byte, so max payload = 5 + 255*7 = 1790 bytes.
"""

from can.can_message import CANMessage

FIRST_FRAME_PAYLOAD = 5      # payload bytes carried by the first frame
CONT_FRAME_PAYLOAD  = 7      # payload bytes carried by each continuation frame
MAX_SEQUENCE        = 255    # sequence number is a single byte
MAX_PAYLOAD         = FIRST_FRAME_PAYLOAD + MAX_SEQUENCE * CONT_FRAME_PAYLOAD  # 1790


def fragment(arbitration_id, payload):
    """Split `payload` (bytes) into a list of <=8-byte CANMessage frames.

    A payload of 5 bytes or fewer produces a single frame.
    """
    if not isinstance(payload, (bytes, bytearray)):
        raise TypeError("payload must be bytes or bytearray")

    total_len = len(payload)
    if total_len > MAX_PAYLOAD:
        raise ValueError(
            f"payload of {total_len} bytes exceeds max {MAX_PAYLOAD} "
            f"for this fragmentation scheme"
        )

    frames = []

    # First frame: 3-byte header (seq=0, length low, length high) + up to 5 bytes.
    header = bytes([0, total_len & 0xFF, (total_len >> 8) & 0xFF])
    first_chunk = bytes(payload[:FIRST_FRAME_PAYLOAD])
    frames.append(CANMessage(arbitration_id, header + first_chunk))

    # Continuation frames.
    offset = FIRST_FRAME_PAYLOAD
    seq = 1
    while offset < total_len:
        chunk = bytes(payload[offset:offset + CONT_FRAME_PAYLOAD])
        frames.append(CANMessage(arbitration_id, bytes([seq]) + chunk))
        offset += CONT_FRAME_PAYLOAD
        seq += 1

    return frames


def reassemble(frames):
    """Rebuild the original payload from a list of fragment CANMessages.

    Frames may arrive out of order; they are sorted by sequence number.

    Before trusting the byte content, the fragment set is validated:
      * every frame shares the same arbitration_id
      * every frame is <= 8 bytes (Classic CAN) and non-empty
      * sequence numbers are exactly 0, 1, 2, ... N-1 -- no duplicates,
        no gaps, nothing out of range
      * the first frame carries a full 3-byte header

    Raises ValueError on any violation, or if the collected byte count
    is short of the length declared in the first frame.
    """
    if not frames:
        raise ValueError("reassemble() received no frames")

    arb_id = frames[0].arbitration_id
    for f in frames:
        if f.arbitration_id != arb_id:
            raise ValueError(
                "frames have inconsistent arbitration_id: "
                f"{f.arbitration_id} vs {arb_id}"
            )
        if len(f.data) == 0:
            raise ValueError("frame has empty data (no sequence byte)")
        if len(f.data) > 8:
            raise ValueError(
                f"frame exceeds 8-byte Classic CAN limit: {len(f.data)} bytes"
            )

    # Order by the sequence byte (frame.data[0]); first frame is sequence 0.
    ordered = sorted(frames, key=lambda f: f.data[0])

    sequences = [f.data[0] for f in ordered]
    expected = list(range(len(ordered)))
    if sequences != expected:
        if len(set(sequences)) != len(sequences):
            raise ValueError(f"duplicate sequence number(s): {sequences}")
        raise ValueError(
            f"missing or non-contiguous sequence number(s): "
            f"got {sequences}, expected {expected}"
        )

    first = ordered[0]
    if len(first.data) < 3:
        raise ValueError("first frame too short to contain length header")

    total_len = first.data[1] | (first.data[2] << 8)

    payload = bytearray(first.data[3:])
    for frame in ordered[1:]:
        payload.extend(frame.data[1:])

    if len(payload) < total_len:
        raise ValueError(
            f"incomplete message: got {len(payload)} bytes, "
            f"expected {total_len}"
        )

    return bytes(payload[:total_len])


class CANBus:
    """In-memory Classic-CAN bus used by the software simulation.

    Unchanged from the original: a simple FIFO queue. Fragmentation is a
    separate concern (the functions above); the bus just carries frames.
    """

    def __init__(self):
        self.queue = []

    def send(self, message):
        self.queue.append(message)

    def receive(self):
        if len(self.queue) == 0:
            return None
        return self.queue.pop(0)