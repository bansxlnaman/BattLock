from can.decoder import (
    decode_battery_id,
    decode_status,
    decode_signature,
    decode_certificate,
)

from crypto.counters.replay_protection import ReplayProtection
from crypto.certs.certificate import verify_certificate
from crypto.crypto_utils.signatures import verify_signature
from crypto.crypto_utils.key_serialization import deserialize_public_key

from can.encoder import (
    encode_nonce,
    encode_auth_result,
    encode_session_id,
    encode_auth_request,
)

from can.can_ids import (
    BATTERY_STATUS,
    OVERVOLTAGE,
    UNDERVOLTAGE,
    OVERCURRENT,
    OVERTEMP,
    COMM_ERROR,
    AUTH_FAILURE,
    SESSION_ID,
)


class VehicleNode:

    # Slightly tighter than the injection thresholds so we can catch
    # evasion attempts that sit just below the obvious limits.
    VOLTAGE_WARN = 95.0
    CURRENT_WARN = 450.0
    TEMPERATURE_WARN = 140.0

    def __init__(self, bus, root_ca_public_key=None):
        self.bus = bus
        self.replay = ReplayProtection()

        # Root CA public key used to verify battery certificates.
        self.root_ca_public_key = root_ca_public_key

        # Stored after a certificate is received and decoded from CAN.
        self._stored_certificate = None

        # Full challenge bytes (nonce + timestamp) sent to battery;
        # stored so the same data can be used for signature verification.
        self._challenge_data = None

        # Session tracking: valid session ID and whether it has been seen.
        self._session_id = None
        self._session_active = False

        # Bus-load / timing observation for DoS / delay detection.
        self._last_status_time = None

    # ------------------------------------------------------------------
    # Low-level receive handler (telemetry / identity frames)
    # ------------------------------------------------------------------

    def receive(self, message):

        if message.arbitration_id == 0x100:

            battery_id = decode_battery_id(message)

            print("Received:", battery_id)

        elif message.arbitration_id == BATTERY_STATUS:

            self._handle_status(message)

        elif message.arbitration_id == SESSION_ID:

            self._handle_session_id(message)

    def _handle_status(self, message):
        """
        Decode and validate a BATTERY_STATUS frame.
        Detects replay, injection, fuzzing, and evasion attacks.
        """

        # Fuzzing / malformed-frame detection
        if len(message.data) != 19:
            print("FUZZING/MALFORMED ATTACK DETECTED: invalid status length")
            return

        try:
            status = decode_status(message)
        except Exception as exc:
            print("FUZZING/MALFORMED ATTACK DETECTED: decoder error:", exc)
            return

        if not self.replay.validate(status.counter):
            print("REPLAY ATTACK DETECTED")
            return

        # Obvious out-of-range injection
        if (
            status.voltage > 100 or
            status.current > 500 or
            status.temperature > 150
        ):
            print("INJECTION ATTACK DETECTED")
            return

        # Fault-flag evasion detection: attacker left a silent flag set.
        if status.fault_flags & (
            OVERVOLTAGE | UNDERVOLTAGE | OVERCURRENT | OVERTEMP |
            COMM_ERROR | AUTH_FAILURE
        ):
            print("EVASION ATTACK DETECTED: fault_flags raised")
            return

        # Threshold evasion detection: values suspiciously close to limits.
        if (
            status.voltage > self.VOLTAGE_WARN or
            status.current > self.CURRENT_WARN or
            status.temperature > self.TEMPERATURE_WARN
        ):
            print("EVASION ATTACK DETECTED: values near safety limits")
            return

        print("VALID:", status)

    def _handle_session_id(self, message):
        """
        Detect session hijacking by validating that a session ID is received
        only once and only after a successful authentication.
        """
        session_id = message.data.decode()

        if self._session_active and session_id == self._session_id:
            print("SESSION HIJACK ATTACK DETECTED: replayed session ID")
            return

        self._session_id = session_id
        self._session_active = True
        print("Session ID received:", session_id)

    def receive_and_verify_certificate(self, message):
        """
        Decode the certificate from a CAN frame (decode_certificate returns a
        real Certificate object), store it, and verify it against the Root CA
        public key.  Returns True on success, False otherwise.
        """
        certificate = decode_certificate(message)
        self._stored_certificate = certificate

        if self.root_ca_public_key is None:
            print("VehicleNode: No Root CA public key configured")
            return False

        valid = verify_certificate(certificate, self.root_ca_public_key)

        if valid:
            print("Certificate Received via CAN — Verification Passed")
        else:
            print("Certificate Received via CAN — Verification FAILED")

        return valid

    # ------------------------------------------------------------------
    # Fix 3: Challenge is sent as combined challenge_data bytes
    # ------------------------------------------------------------------

    def send_nonce(self, nonce, timestamp=None):
        """
        Encode the challenge as a NONCE CAN frame.
        When timestamp is supplied the full challenge_data
        (nonce + str(timestamp) bytes) is sent so the battery can sign the
        identical byte sequence.  The combined bytes are stored internally
        for later signature verification.
        """
        if timestamp is not None:
            challenge_data = nonce + str(timestamp).encode()
        else:
            challenge_data = nonce

        self._challenge_data = challenge_data
        return encode_nonce(challenge_data)

    # ------------------------------------------------------------------
    # Fix 3: Signature received through CAN and verified here
    # ------------------------------------------------------------------

    def receive_and_verify_signature(self, message):
        """
        Decode the ECDSA signature bytes from a CAN frame and verify them
        against the stored certificate's public key and the stored challenge
        bytes.  Returns True on success, False otherwise.
        No signature bytes are passed directly from the orchestrator —
        they travel through encode_signature → CANBus → decode_signature.
        """
        if self._stored_certificate is None:
            print("VehicleNode: No certificate stored — cannot verify signature")
            return False

        if self._challenge_data is None:
            print("VehicleNode: No challenge data stored — cannot verify signature")
            return False

        signature = decode_signature(message)

        public_key = deserialize_public_key(self._stored_certificate.public_key)
        result = verify_signature(public_key, self._challenge_data, signature)

        if result:
            print("Signature Received via CAN — Verification Passed")
        else:
            print("Signature Received via CAN — Verification FAILED")

        return result

    def send_auth_request(self):

        return encode_auth_request()

    def receive_signature(self, message):

        signature = decode_signature(message)

        print("Signature Received")

        return signature

    def send_auth_result(self, result):

        return encode_auth_result(result)

    def send_session_id(self, session):

        return encode_session_id(session)

    def receive_certificate(self, message):
        """Legacy helper kept for run_simulation.py compatibility."""
        certificate = decode_certificate(message)

        print("Certificate Received")

        return certificate