# BattLock CAN Transport Contract

**Owner:** Person 3 (CAN Protocol / Software)
**Audience:** Person 4 (Hardware / ESP32 + MCP2515)
**Status:** Software reference implementation complete (`can/` module). Hardware
side must match this document byte-for-byte.

This document is the single source of truth for how BattLock messages travel
over the CAN bus. The Python `can/` module implements exactly what is described
here; the ESP32 firmware must produce and consume the identical byte layouts,
otherwise the two sides will not interoperate.

---

## 1. Physical layer assumptions

| Property | Value |
|---|---|
| Bus type | Classic CAN (CAN 2.0A) |
| Identifier | 11-bit standard identifiers |
| Max data per frame | 8 bytes |
| Bitrate | 500 kbps |
| Byte order (multi-byte fields) | **Little-endian** (must match ESP32 native) |

Every field wider than one byte — lengths, `counter`, all floats — is
little-endian. This is deliberate so the ESP32 can pack/unpack with native
byte order. Do not change this without updating both sides.

---

## 2. CAN identifier table

| ID | Name | Direction | Payload |
|---|---|---|---|
| `0x100` | `AUTH_REQUEST` | Vehicle → Battery | `b"AUTH"` (4 B) |
| `0x100` | Battery ID | Battery → Vehicle | ASCII battery id (e.g. `"BAT001"`) |
| `0x101` | `NONCE` | Vehicle → Battery | 32-byte challenge (+ timestamp when combined) |
| `0x102` | `SIGNATURE` | Battery → Vehicle | ECDSA P-256 signature (~64–72 B, DER) |
| `0x103` | `AUTH_RESULT` | Vehicle → Battery | 1 byte (0 / 1) |
| `0x104` | `CERTIFICATE` | Battery → Vehicle | JSON certificate (~148–483 B) |
| `0x105` | `SESSION_ID` | Vehicle → Battery | 32-byte hex session id |
| `0x200` | `BATTERY_STATUS_A` | Battery → Vehicle | counter, SOC, SOH, fault (8 B) |
| `0x201` | `BATTERY_STATUS_B` | Battery → Vehicle | voltage, current (8 B) |
| `0x202` | `BATTERY_STATUS_C` | Battery → Vehicle | temperature (8 B) |

**Note — `0x100` is overloaded** in the current design: it carries both the
`AUTH_REQUEST` marker and the battery-id message, distinguished by direction
and payload content. This is existing behavior, flagged here so the hardware
side is aware; changing it is out of scope for the transport contract.

### Fault-flag bitmask (used in `STATUS_A`)

| Flag | Value |
|---|---|
| `OVERVOLTAGE` | `0x01` |
| `UNDERVOLTAGE` | `0x02` |
| `OVERCURRENT` | `0x04` |
| `OVERTEMP` | `0x08` |
| `COMM_ERROR` | `0x10` |
| `AUTH_FAILURE` | `0x20` |

`fault_flags` is transmitted as a **single byte** in `STATUS_A`, so only the
low 8 bits are carried. All defined flags fit within one byte.

---

## 3. Single-frame vs multi-frame messages

Messages whose payload is ≤ 8 bytes are sent as one frame with no framing
overhead:

- `AUTH_REQUEST` (4 B), `AUTH_RESULT` (1 B), Battery ID (≤ 8 B)
- `BATTERY_STATUS_A / _B / _C` (8 B each — see §5)

Messages whose payload exceeds 8 bytes MUST use the multi-frame fragmentation
scheme in §4:

- `NONCE` (32 B) → 5 frames
- `SIGNATURE` (~64–72 B) → ~10–11 frames
- `CERTIFICATE` (~148–483 B) → ~22–70 frames
- `SESSION_ID` (32 B) → 5 frames

---

## 4. Multi-frame fragmentation scheme

This is a BattLock-specific scheme (not ISO-TP). All fragments of one payload
share the **same arbitration ID** as the logical message.

### First frame (sequence 0)

| Byte | Meaning |
|---|---|
| 0 | sequence number = `0` |
| 1 | total payload length, low byte |
| 2 | total payload length, high byte |
| 3–7 | up to 5 payload bytes |

### Continuation frames (sequence 1, 2, … N)

| Byte | Meaning |
|---|---|
| 0 | sequence number (1-based, increments by 1) |
| 1–7 | up to 7 payload bytes |

### Rules

- Total payload length is a **16-bit little-endian** value in the first frame.
  The receiver uses it to know when the message is complete — there is **no
  separate end-of-message flag**.
- Sequence number is a single byte, so the maximum payload is
  `5 + 255 × 7 = 1790 bytes`.
- A payload of ≤ 5 bytes produces a single (first) frame.
- The last continuation frame may carry fewer than 7 bytes; frames are **not**
  padded to 8. (Classic CAN permits DLC < 8.)

### Worked example — 32-byte nonce

```
Frame 0: [00][20][00][b0 b1 b2 b3 b4]      seq 0, len=0x0020=32,  5 bytes
Frame 1: [01][b5 .. b11]                   seq 1,                  7 bytes
Frame 2: [02][b12 .. b18]                  seq 2,                  7 bytes
Frame 3: [03][b19 .. b25]                  seq 3,                  7 bytes
Frame 4: [04][b26 .. b31]                  seq 4,                  6 bytes
Total: 5 + 7 + 7 + 7 + 6 = 32 bytes
```

---

## 5. Reassembly rules

The receiver collects all fragments of one arbitration ID, then:

1. **Validates the set before trusting content:**
   - every frame shares the same arbitration ID
   - every frame is non-empty and ≤ 8 bytes
   - sequence numbers are exactly `0, 1, 2, … N-1` — no duplicates, no gaps
   - the first frame is at least 3 bytes (header present)
2. Reads the 16-bit little-endian total length from the first frame.
3. Concatenates: first frame bytes `3:` then each continuation's bytes `1:`.
4. Truncates to the declared total length and returns the payload.
5. Raises / errors if the collected byte count is short of the declared length.

Any violation (missing first frame, duplicate/gap in sequence, oversized
frame, mixed IDs) is a hard error — the message is rejected, not guessed at.

---

## 6. Status frame byte layouts

Battery telemetry (`BatteryStatus`) is split across three 8-byte frames. All
fields little-endian.

### `0x200` STATUS_A — `<IBBBB`

| Bytes | Field | Type |
|---|---|---|
| 0–3 | `counter` | uint32 |
| 4 | `soc` | uint8 |
| 5 | `soh` | uint8 |
| 6 | `fault_flags` | uint8 |
| 7 | reserved | `0x00` |

### `0x201` STATUS_B — `<ff`

| Bytes | Field | Type |
|---|---|---|
| 0–3 | `voltage` | float32 |
| 4–7 | `current` | float32 |

### `0x202` STATUS_C — `<f4x`

| Bytes | Field | Type |
|---|---|---|
| 0–3 | `temperature` | float32 |
| 4–7 | reserved | `0x00 00 00 00` |

The reserved bytes keep A and C at a fixed 8-byte size so the hardware has a
predictable frame length to allocate.

---

## 7. Status collector policy (receiver side)

A single status frame is not actionable on its own; the receiver must collect
a full A → B → C round before aggregating into a `BatteryStatus` and running
replay / injection / telemetry logic. The reference implementation is
`can/status_collector.py`. The ESP32 side must follow the same policy:

- **`STATUS_A` (0x200) begins a round.** It carries the `counter`. Receiving a
  `STATUS_A` always starts a fresh round and discards any incomplete partial
  round still buffered.
- **`STATUS_B` / `STATUS_C` are accepted only while a round is open** (a
  `STATUS_A` has been seen). Orphan B/C frames with no open round are ignored.
- **A `BatteryStatus` is produced only when A, B and C are all present**, after
  which the buffer resets.
- **If B or C is lost, the next `STATUS_A` discards the incomplete round.** That
  telemetry sample is dropped — this is the intended safe behavior.

Because `STATUS_A` has the lowest ID (`0x200`), it wins CAN arbitration over B
and C, so the natural on-bus order is A → B → C, which this policy assumes.

---

## 8. Implementation status

| Piece | Status |
|---|---|
| CAN ID table (`can_ids.py`) | Done — A/B/C added, `BATTERY_STATUS` alias kept |
| Fragmentation (`transport.fragment`) | Done + tested |
| Reassembly (`transport.reassemble`) | Done + hardened + tested |
| Status A/B/C encode/decode + aggregator | Done + tested |
| Status collector | Done + tested |
| Wiring transport into auth flow (nonce/sig/cert) | **Phase 4 — pending** |
| Wiring collector into vehicle node | **Phase 4 — pending** |
| 8-byte enforcement in `CANMessage` | **Phase 5 — pending** (turned on last) |

Until Phase 5, `CANMessage` does **not** enforce the 8-byte limit, so the
legacy single-frame `encode_status()` / `encode_nonce()` / `encode_certificate()`
still emit oversized blobs for backward compatibility. The 8-byte check is
switched on only after every path routes through the fragmentation layer.

---

## 9. Open items to resolve before hardware bring-up

- **Fragment timeout:** on real hardware, define how long a receiver waits for
  the rest of a fragmented message before discarding the partial set. The
  software sim has no timing, so this is unspecified here and must be decided
  with Person 4.
- **DLC handling:** confirm the MCP2515 driver transmits the actual data length
  (DLC < 8 for short final frames) rather than always padding to 8.
- **Bus error / retransmit behavior:** out of scope for this contract; to be
  defined during hardware integration.
