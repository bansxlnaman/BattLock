"""
Serial-backed ATECC608B hardware provider.

Talks to the ATECC608B secure element over USB serial via the
`hardware/atecc_bridge.ino` sketch running on the battery ESP32.

Implements the same provider interface as SoftwareKeys (connect / sign /
get_public_key) so KeyManager can use it transparently.

Command protocol (ASCII over serial, 115200 baud):
    PING                                  -> PONG
    SIGN <64-hex-chars>                   -> SIG:<128 hex>
    PUBKEY                                -> PUB:<128 hex>
    GENKEY                                -> OK
    VERIFY <msg> <sig> <pub> (hex)        -> VERIFY:1 / VERIFY:0
"""

from crypto.crypto_utils.signatures import RAW_SIG_LEN

try:
    import serial
    _HAS_SERIAL = True
except ImportError:
    _HAS_SERIAL = False


class ATECC608:

    def __init__(self, port="COM5", baud=115200, timeout=2.0):
        self.port = port
        self.baud = baud
        self.timeout = timeout
        self._ser = None
        self.connected = False

    def connect(self):
        """Open the serial link to the bridge and confirm the chip responds."""
        if not _HAS_SERIAL:
            raise RuntimeError(
                "pyserial is required for hardware access. "
                "Install it with: python -m pip install pyserial"
            )
        self._ser = serial.Serial(self.port, self.baud, timeout=self.timeout)
        self._ser.reset_input_buffer()
        if self._query("PING") != "PONG":
            self._ser.close()
            self._ser = None
            raise ConnectionError(f"ATECC bridge not responding on {self.port}")
        self.connected = True

    def _query(self, line):
        self._ser.write((line + "\n").encode())
        resp = self._ser.readline().decode(errors="replace").strip()
        return resp

    def sign(self, data: bytes):
        """Sign a 32-byte message on the chip; returns raw 64-byte R||S."""
        if not self.connected:
            raise RuntimeError("ATECC608: call connect() first")
        if len(data) != 32:
            raise ValueError("ATECC608.sign: message must be 32 bytes")
        resp = self._query("SIGN " + data.hex())
        if not resp.startswith("SIG:"):
            raise RuntimeError(f"sign failed: {resp}")
        raw = bytes.fromhex(resp[4:])
        if len(raw) != RAW_SIG_LEN:
            raise RuntimeError(f"sign returned {len(raw)} bytes, expected {RAW_SIG_LEN}")
        return raw

    def get_public_key(self):
        """Return the chip's public key as a cryptography key object.

        Interface-compatible with SoftwareKeys.get_public_key() so the
        integration layer can call serialize_public_key() on the result.
        """
        if not self.connected:
            raise RuntimeError("ATECC608: call connect() first")
        resp = self._query("PUBKEY")
        if not resp.startswith("PUB:"):
            raise RuntimeError(f"get_public_key failed: {resp}")
        raw = bytes.fromhex(resp[4:])
        return self._raw_pubkey_to_key(raw)

    @staticmethod
    def _raw_pubkey_to_key(raw):
        """Convert raw 64-byte X||Y public key to a cryptography key object."""
        from cryptography.hazmat.primitives.asymmetric import ec

        # SEC1 uncompressed point = 0x04 || X || Y
        point = b"\x04" + raw
        return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), point)

    def genkey(self):
        """Create a new keypair in slot 0 (used by provisioning)."""
        if not self.connected:
            raise RuntimeError("ATECC608: call connect() first")
        resp = self._query("GENKEY")
        if resp != "OK":
            raise RuntimeError(f"genkey failed: {resp}")

    def close(self):
        if self._ser is not None:
            self._ser.close()
            self._ser = None
        self.connected = False
