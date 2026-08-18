# BattLock Hardware — Arduino Firmware

ESP32 + MCP2515 + ATECC608A firmware implementing the BattLock protocol.
Two sketches mirror the Python implementation in the repo:

- `battery.ino`  — battery module: identity, certificate, challenge signing, telemetry
- `vehicle.ino`  — vehicle/ECU: certificate + signature verification, replay/injection checks

Both include `battlock_protocol.h` (CAN IDs, state machine, fragmentation).

## How it maps to the Python code

| Concept | Python | Arduino |
|---------|--------|---------|
| CAN IDs | `can/can_ids.py` | `CAN_ID_*` in `battlock_protocol.h` |
| State machine | `protocol/state_machine.py` | `BattLockState` enum |
| Status layout | `can/encoder.py` (`IfffBBB`) | 2-frame telemetry (8-byte CAN limit) |
| Replay | `crypto/counters/replay_protection.py` | `last_counter` check in `vehicle.ino` |
| Injection | `can/simulation/vehicle_node.py` | voltage/current threshold check |
| Cert verify | `crypto/certs/certificate.py` | `verify_certificate()` in `vehicle.ino` |

## Wiring (defaults — confirm with hardware team)

| MCP2515 | ESP32 |
|---------|-------|
| CS | GPIO 5 |
| INT | GPIO 4 |
| MOSI | GPIO 23 |
| MISO | GPIO 19 |
| SCK | GPIO 18 |
| VCC / GND | 3.3V / GND |

| ATECC608A | ESP32 |
|-----------|-------|
| SDA | GPIO 21 |
| SCL | GPIO 22 |
| VCC / GND | 3.3V / GND |

120 Ω termination at both ends of the CAN bus (required).

## Libraries (Arduino IDE / PlatformIO)

- `mcp_can` (MCP2515 driver) — `https://github.com/coryjfowler/mcp_can`
- `arduino-cryptolib` (ATECC608A + SHA-256) — `https://github.com/Ropg/arduino-cryptolib`

Install both via Library Manager.

## Important notes before flashing

1. **CAN payload is 8 bytes max.** The Python status frame (`IfffBBB` = 19
   bytes) and the certificate / nonce / signature do not fit one frame, so
   they are split with a fragmentation scheme. Fragment 0 carries the total
   payload length (bytes 1–2) plus 5 data bytes; fragments 1..n-1 carry 7
   data bytes; the last fragment sets a flag. See `battlock_protocol.h`.

2. **The ATECC608A API is a placeholder.** The sketches call
   `atecc.ecdsaSign()`, `atecc.ecdsaVerify()`, and `atecc.begin()`. Check
   the exact method names in the installed arduino-cryptolib version — the
   API differs across releases. Same for the nonce generation (`millis()`
   placeholder) and the root CA public key / certificate data (all zeroed).

3. **Provisioning is NOT automated.** These must be done before flashing:
   - Generate a keypair and store the battery private key in an ATECC608A slot.
   - Have the manufacturer sign the battery's certificate and store the
     root CA public key on the vehicle's ATECC608A (or in flash).
   - Fill in `battery_cert` in `battery.ino` and `root_ca_public_key` in
     `vehicle.ino`.

4. **Baud rate** — both sketches use 500 kbps (`CAN_500KBPS`). Change in
   both files if the hardware uses 125 kbps.

5. **SDA/SCL and the ATECC address** — defaults are GPIO 21/22 and `0x60`.
   Adjust to the actual wiring.

## Status of this code

Drafted from the repo protocol. **Not yet compiled/flashed** — it is a
starting point for the hardware team to adapt to the exact wiring, the
installed library APIs, and the provisioning data. Compile each sketch in its
own Arduino sketch folder with `battlock_protocol.h` beside it.
