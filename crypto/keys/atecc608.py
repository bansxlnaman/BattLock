"""
Serial-backed ATECC608B hardware provider.

Talks to the ATECC608B over USB serial via hardware/atecc_bridge.ino
running on the battery ESP32.  Implements the same interface as
SoftwareKeys so KeyManager can swap transparently.

Protocol (ASCII, 115200 baud, one command per line):
    PING                    -> PONG
    SIGN <64-hex-chars>     -> SIG:<128-hex>  (raw 64-byte R||S)
    PUBKEY                  -> PUB:<128-hex>  (64-byte X||Y)
    GENKEY                  -> OK             (creates keypair in slot 0)
    VERIFY <msg> <sig> <pub> (hex) -> VERIFY:1 / VERIFY:0
"""

try:
    import serial as _serial
    _HAS_SERIAL = True
except ImportError:
    _HAS_SERIAL = False

from crypto.crypto_utils.signatures import RAW_SIG_LEN


class ATECC608:

    def __init__(self, port="COM3", baud=115200, timeout=2.0, slot=0):
        self.port = port
        self.baud = baud
        self.timeout = timeout
        self.slot = slot
        self._ser = None
        self.connected = False

    def connect(self):
        """Open serial link, ping the bridge, confirm the chip is alive."""
        if not _HAS_SERIAL:
            raise RuntimeError(
                "pyserial is required for hardware access. "
                "Install with: python -m pip install pyserial"
            )
        self._ser = _serial.Serial(self.port, self.baud, timeout=self.timeout)
        self._ser.reset_input_buffer()
        resp = self._query("PING")
        if resp != "PONG":
            self._ser.close()
            self._ser = None
            raise ConnectionError(
                f"ATECC bridge not responding on {self.port} (got: {resp!r})"
            )
        self.connected = True

    # ── low-level helpers ────────────────────────────────────────────

    def _query(self, line):
        """Send a line, read the response, strip whitespace."""
        self._ser.write((line + "\n").encode())
        resp = self._ser.readline().decode(errors="replace").strip()
        return resp

    # ── provider interface (matches SoftwareKeys) ────────────────────

    def sign(self, data: bytes) -> bytes:
        """Sign a 32-byte message; returns raw 64-byte R||S."""
        if not self.connected:
            raise RuntimeError("ATECC608: call connect() first")
        if len(data) != 32:
            raise ValueError(f"sign requires 32-byte message, got {len(data)}")
        resp = self._query("SIGN " + data.hex())
        if not resp.startswith("SIG:"):
            raise RuntimeError(f"sign failed: {resp!r}")
        raw = bytes.fromhex(resp[4:])
        if len(raw) != RAW_SIG_LEN:
            raise RuntimeError(
                f"sign returned {len(raw)} bytes, expected {RAW_SIG_LEN}"
            )
        return raw

    def get_public_key(self):
        """Return the chip's public key as a cryptography key object."""
        if not self.connected:
            raise RuntimeError("ATECC608: call connect() first")
        resp = self._query("PUBKEY")
        if not resp.startswith("PUB:"):
            raise RuntimeError(f"get_public_key failed: {resp!r}")
        raw = bytes.fromhex(resp[4:])
        return self._raw_pubkey_to_key(raw)

    def get_public_key_pem(self) -> bytes:
        """PEM-serialized public key (convenience for crypto_api)."""
        from crypto.crypto_utils.key_serialization import serialize_public_key
        return serialize_public_key(self.get_public_key())

    def genkey(self):
        """Create a new keypair in slot 0 (used during provisioning)."""
        if not self.connected:
            raise RuntimeError("ATECC608: call connect() first")
        resp = self._query("GENKEY")
        if resp != "OK":
            raise RuntimeError(f"genkey failed: {resp!r}")

    def close(self):
        if self._ser is not None:
            self._ser.close()
            self._ser = None
        self.connected = False

    # ── format conversion ────────────────────────────────────────────

    @staticmethod
    def _raw_pubkey_to_key(raw):
        """Convert raw 64-byte X||Y to a cryptography public key object."""
        from cryptography.hazmat.primitives.asymmetric import ec
        # SEC1 uncompressed point = 0x04 || X || Y
        point = b"\x04" + raw
        return ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), point
        )
