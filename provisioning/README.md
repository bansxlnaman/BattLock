# BattLock Provisioning & Hardware Cross-Test

This folder contains the Crypto/Security Lead's hardware tooling. It makes the
physical ATECC608B secure element work with the Python crypto layer.

## Hardware setup

| Component | Connection |
|-----------|-----------|
| ATECC608B breakout | Battery ESP32 — SDA→GPIO21, SCL→GPIO22, VCC→3.3V, GND→GND (Adafruit board has built-in pull-ups) |
| Battery ESP32 | USB → laptop COM5 |
| Vehicle ESP32 | USB → laptop COM4 |

The bridge sketch (`hardware/atecc_bridge.ino`) runs on the **battery** ESP32
and exposes the chip over USB serial. The laptop talks to the chip through it.

## Serial command protocol (115200 baud)

| Command | Response |
|---------|----------|
| `PING` | `PONG` |
| `SIGN <64-hex>` | `SIG:<128-hex>` (raw 64-byte R\|\|S signature) |
| `PUBKEY` | `PUB:<128-hex>` (64-byte X\|\|Y public key) |
| `GENKEY` | `OK` (creates new keypair in slot 0) |
| `VERIFY <msg> <sig> <pub>` (hex) | `VERIFY:1` or `VERIFY:0` |

## Procedure

### 1. Flash the bridge

Arduino IDE → open `hardware/atecc_bridge.ino` → board "DOIT ESP32 DEVKIT V1" →
select COM5 → Upload. (Library: *SparkFun ATECCX08a Arduino Library*.)

### 2. Provision the chip (once per chip)

```powershell
python provisioning/provision.py --port COM5
```

This creates the battery private key **inside the chip** (it can never be read
out), reads the public key, and issues the Root-CA-signed certificate.
Artifacts land in `provisioning/out/`:

| File | Goes to |
|------|---------|
| `battery_certificate.json` | battery.ino (`battery_cert`) |
| `battery_public_key.pem` | certificate public key field |
| `root_ca_public_key.pem` | vehicle.ino (`root_ca_public_key`) |
| `root_ca_private_key.pem` | **lab only — never put on the vehicle** |

### 3. Cross-compatibility test

```powershell
python provisioning/cross_compat_test.py --port COM5
```

Proves the hardware and Python crypto agree:
- **[A]** chip signs a nonce, Python verifies it
- **[B]** Python signs a nonce, the chip verifies it
- **[C]** a tampered signature is rejected by the chip

If all three pass, the crypto layer is integration-ready.

## Notes

- Python needs `pyserial` (`python -m pip install pyserial`).
- `GENKEY` only works while the chip's config zone allows it; once locked,
  key 0 is permanent. Provision before final flashing.
- Keep `--port` pointed at the **battery** ESP32 (COM5). The vehicle ESP32
  (COM4) has no ATECC attached — it's the verifier side.
