# BattLock Provisioning & Hardware Cross-Test

Crypto/Security Lead tooling — makes the physical ATECC608B work with the Python crypto layer.

## Hardware setup

| Component | Connection |
|-----------|-----------|
| ATECC608B breakout | Battery ESP32 — SDA→GPIO21, SCL→GPIO22, VCC→3.3V, GND→GND |
| Battery ESP32 (DEVKIT V1) | USB → laptop **COM3** |
| Vehicle ESP32 (WROOM) | USB → laptop **COM6** |

The Adafruit ATECC608B breakout has built-in pull-ups — no level shifter needed for I2C.

## Serial command protocol (115200 baud)

| Command | Response |
|---------|----------|
| `PING` | `PONG` |
| `SIGN <64-hex>` | `SIG:<128-hex>` (raw 64-byte R\|\|S) |
| `PUBKEY` | `PUB:<128-hex>` (64-byte X\|\|Y) |
| `GENKEY` | `OK` (creates keypair in slot 0) |
| `VERIFY <msg> <sig> <pub>` (hex) | `VERIFY:1` or `VERIFY:0` |

## Steps

### 1. Flash the bridge

Arduino IDE → `hardware/atecc_bridge.ino` → board "DOIT ESP32 DEVKIT V1" → COM3 → Upload.

Required library: **SparkFun ATECCX08a Arduino Library**.

### 2. Provision the chip (once)

```powershell
python provisioning/provision.py --port COM3
```

Creates the battery private key **inside the chip** (never readable), reads the public key, issues the Root-CA-signed certificate.

Outputs in `provisioning/out/`:

| File | Goes to |
|------|---------|
| `battery_certificate.json` | `battery_cert` in battery.ino |
| `battery_public_key.pem` | Certificate public key field |
| `root_ca_public_key.pem` | `root_ca_public_key` in vehicle.ino |
| `root_ca_private_key.pem` | Lab only — never on the vehicle |

### 3. Cross-compatibility test

```powershell
python provisioning/cross_compat_test.py --port COM3
```

Proves hardware and Python agree:
- **[A]** chip signs → Python verifies
- **[B]** Python signs → chip verifies
- **[C]** tampered signature → chip rejects

All 3 pass = crypto layer is integration-ready.

## Dependencies

- `pyserial` (`python -m pip install pyserial`)
- `cryptography` (already in project)
