import time
import platform
from datetime import datetime, timedelta

from integration.logger import BattLockLogger
from integration.metrics import MetricsCollector

from crypto.certs.root_ca import RootCA
from crypto.certs.certificate import (
    create_certificate,
)

from crypto.crypto_utils.key_serialization import (
    serialize_public_key
)
from can.transport import CANBus

from crypto.auth.challenge import (
    create_challenge
)
from crypto.auth.session import (
    create_session
)

from protocol.session_manager import (
    SessionManager
)
from protocol.state_machine import (
    BattLockStateMachine,
    ConnectionState,
)

from crypto.models.battery import Battery

from crypto.keys.key_manager import KeyManager

from can.simulation.vehicle_node import VehicleNode
from can.simulation.battery_node import BatteryNode


class BattLockOrchestrator:

    def __init__(self):

        self.logger = BattLockLogger()

        self.metrics = MetricsCollector()

        self.session_manager = SessionManager()

        self.state_machine = BattLockStateMachine()

    def log_can_message(self, frame):

        payload_size = len(frame.data)

        # Simulated latency placeholder (Phase-1; real timing comes with HW).
        latency = 0.1

        self.metrics.record_can(
            payload_size,
            latency
        )

    def _transition(self, transition_name, transition_fn):
        """
        Execute a state machine transition.
        Logs the new state on success; logs an error and returns False on
        invalid transition so the caller can abort.
        """
        result = transition_fn()

        current = self.state_machine.get_state().name

        if result:
            self.logger.info(
                f"[STATE] {transition_name} → {current}"
            )
        else:
            self.logger.info(
                f"[STATE ERROR] Transition '{transition_name}' failed "
                f"(current state: {current}) — Aborting authentication"
            )

        return result

    # ------------------------------------------------------------------
    # Main execution
    # ------------------------------------------------------------------

    def run(self):

        overall_start = time.perf_counter()

        # ==================================================
        # PHASE 1 : SYSTEM INITIALIZATION
        # ==================================================

        self.logger.info(
            "\n========================="
        )

        self.logger.info(
            "BATTLOCK SYSTEM STARTUP"
        )

        self.logger.info(
            "=========================\n"
        )

        self.logger.info(
            f"Timestamp: {datetime.now()}"
        )

        self.logger.info(
            f"Python Version: {platform.python_version()}"
        )

        self.logger.info(
            f"Operating System: {platform.system()}"
        )

        self.logger.info(
            f"Initial State: {self.state_machine.get_state().name}"
        )

        # ==================================================
        # PHASE 2 : ROOT CA
        # ==================================================

        self.logger.info(
            "\n[PHASE 2] ROOT CA INITIALIZATION"
        )

        self.metrics.start(
            "root_ca_generation"
        )

        root_ca = RootCA()

        self.metrics.stop(
            "root_ca_generation"
        )

        self.logger.info(
            "Root CA Ready"
        )

        # ==================================================
        # PHASE 3 : BATTERY KEYS
        # ==================================================

        self.logger.info(
            "\n[PHASE 3] BATTERY PROVISIONING"
        )

        self.metrics.start(
            "battery_key_generation"
        )

        battery = Battery(
            battery_id="BAT001",
            serial_number="SN0001",
            manufacturer_id="BATTLOCK"
        )

        battery_public_key = serialize_public_key(
            battery.get_public_key()
        )
        self.metrics.stop(
            "battery_key_generation"
        )

        self.logger.info(
            "Battery ID: BAT001"
        )

        self.logger.info(
            "Battery Public Key Generated"
        )

        self.logger.info(
            "Private Key Stored Securely (SoftwareKeys)"
        )

        # ==================================================
        # PHASE 4 : CERTIFICATE GENERATION
        # ==================================================

        self.logger.info(
            "\n[PHASE 4] CERTIFICATE ISSUANCE"
        )

        self.metrics.start(
            "certificate_generation"
        )

        certificate = create_certificate(
            root_ca=root_ca,
            battery_id="BAT001",
            manufacturer_id="BATTLOCK",
            battery_public_key=battery_public_key,
            issue_date=datetime.now().strftime("%Y-%m-%d"),
            expiry_date=(
                datetime.now() + timedelta(days=365)
            ).strftime("%Y-%m-%d")
        )

        self.metrics.stop(
            "certificate_generation"
        )

        self.logger.info(
            "Certificate Generated"
        )

        self.logger.info(
            f"Manufacturer ID: {certificate.manufacturer_id}"
        )

        self.logger.info(
            f"Battery ID: {certificate.battery_id}"
        )

        self.logger.info(
            f"Expiry Date: {certificate.expiry_date}"
        )

        battery.certificate = certificate

        # ==================================================
        # PHASE 5 : CAN NETWORK STARTUP
        # ==================================================

        self.logger.info(
            "\n[PHASE 5] CAN NETWORK STARTUP"
        )

        bus = CANBus()

        vehicle = VehicleNode(
            bus=bus,
            root_ca_public_key=root_ca.public_key
        )

        battery_node = BatteryNode(
            battery,
            bus=bus
        )

        self.logger.info(
            "CAN Network Online"
        )

        self.logger.info(
            "Vehicle Node Registered"
        )

        self.logger.info(
            "Battery Node Registered"
        )

        # ==================================================
        # PHASE 6 : AUTH REQUEST  (Vehicle → Battery)
        # ==================================================

        self.logger.info(
            "\n[PHASE 6] AUTHENTICATION START"
        )

        self.logger.info(
            "\nVehicle → Battery"
        )

        self.logger.info(
            "CAN ID: 0x100  |  AUTH_REQUEST"
        )

        auth_msg = vehicle.send_auth_request()
        bus.send(auth_msg)
        self.log_can_message(auth_msg)

        # Battery side consumes the auth-request frame.
        bus.receive()

        # ==================================================
        # PHASE 7 : CERTIFICATE EXCHANGE  (Battery → Vehicle via CAN)
        # ==================================================

        self.logger.info(
            "\n[PHASE 7] CERTIFICATE EXCHANGE"
        )

        self.logger.info(
            "\nBattery → Vehicle"
        )

        self.logger.info(
            "CAN ID: 0x104  |  CERTIFICATE"
        )

        cert_msg = battery_node.send_certificate(certificate)
        bus.send(cert_msg)
        self.log_can_message(cert_msg)

        received_cert_msg = bus.receive()
        self.log_can_message(received_cert_msg)

        # ==================================================
        # PHASE 8 : CERTIFICATE VERIFICATION
        # ==================================================

        self.logger.info(
            "\n[PHASE 8] CERTIFICATE VERIFICATION"
        )

        self.metrics.start(
            "certificate_verification"
        )

        # hello_received() fires when we see the battery's first message.
        if not self._transition(
            "hello_received",
            self.state_machine.hello_received
        ):
            return

        cert_valid = vehicle.receive_and_verify_certificate(received_cert_msg)

        self.metrics.stop(
            "certificate_verification"
        )

        if not cert_valid:
            self.logger.info(
                "Certificate Verification Failed — Aborting"
            )
            return

        self.logger.info(
            "Certificate Verification Successful"
        )

        if not self._transition(
            "certificate_verified",
            self.state_machine.certificate_verified
        ):
            return

        # ==================================================
        # PHASE 9 : CHALLENGE GENERATION + CAN TRANSMISSION
        # ==================================================

        self.logger.info(
            "\n[PHASE 9] CHALLENGE GENERATION"
        )

        challenge = create_challenge()

        self.logger.info(
            "Challenge Created"
        )

        self.logger.info(
            f"Nonce Length: {len(challenge.nonce)} bytes"
        )

        self.logger.info(
            "\nVehicle → Battery"
        )

        self.logger.info(
            "CAN ID: 0x101  |  NONCE + TIMESTAMP"
        )

        # send_nonce combines nonce + str(timestamp) and stores challenge_data
        # internally for later signature verification.
        nonce_msg = vehicle.send_nonce(
            challenge.nonce,
            challenge.timestamp
        )

        bus.send(nonce_msg)
        self.log_can_message(nonce_msg)

        if not self._transition(
            "challenge_sent",
            self.state_machine.challenge_sent
        ):
            return

        # ==================================================
        # PHASE 10 : BATTERY SIGNS VIA CAN
        # ==================================================

        self.logger.info(
            "\n[PHASE 10] BATTERY SIGNATURE GENERATION"
        )

        # Battery receives the challenge from the CAN bus.
        received_challenge_msg = bus.receive()
        self.log_can_message(received_challenge_msg)

        battery_node.receive_nonce(received_challenge_msg)

        self.logger.info(
            "\nBattery → Vehicle"
        )

        self.logger.info(
            "CAN ID: 0x102  |  SIGNATURE"
        )

        self.metrics.start(
            "signature_generation"
        )

        # BatteryNode signs the stored challenge_data and encodes the
        # signature into a CAN message — no direct signing in orchestrator.
        sig_msg = battery_node.sign_and_respond()

        self.metrics.stop(
            "signature_generation"
        )

        bus.send(sig_msg)
        self.log_can_message(sig_msg)

        # ==================================================
        # PHASE 11 : SIGNATURE VERIFICATION VIA CAN
        # ==================================================

        self.logger.info(
            "\n[PHASE 11] SIGNATURE VERIFICATION"
        )

        self.metrics.start(
            "signature_verification"
        )

        received_sig_msg = bus.receive()
        self.log_can_message(received_sig_msg)

        result = vehicle.receive_and_verify_signature(received_sig_msg)

        self.metrics.stop(
            "signature_verification"
        )

        if result:

            self.logger.info(
                "Challenge Verification Passed"
            )

            if not self._transition(
                "authenticated",
                self.state_machine.authenticated
            ):
                return

            # ------------------------------------------------------
            # SESSION ESTABLISHMENT
            # ------------------------------------------------------

            self.logger.info(
                "\nCreating Session..."
            )

            session = create_session(
                battery.identity.battery_id
            )

            self.session_manager.add_session(
                session.session_id,
                session.battery_id
            )

            self.logger.info(
                f"Session ID: {session.session_id}"
            )

            self.logger.info(
                f"Battery ID: {session.battery_id}"
            )

            self.logger.info(
                "\nVehicle → Battery"
            )

            self.logger.info(
                "CAN ID: 0x105  |  SESSION_ID"
            )

            session_msg = vehicle.send_session_id(session)
            self.log_can_message(session_msg)
            bus.send(session_msg)

            received_session = bus.receive()
            self.log_can_message(received_session)

            battery_node.receive_session_id(received_session)

            if not self._transition(
                "session_established",
                self.state_machine.session_established
            ):
                return

            self.logger.info(
                "\nBATTERY AUTHENTICATED"
            )

            self.logger.info(
                "SECURE SESSION ACTIVE"
            )

            self.logger.info(
                f"Final State: {self.state_machine.get_state().name}"
            )

            # Verify acceptance test: state must be ACTIVE_SESSION
            assert self.state_machine.get_state() == ConnectionState.ACTIVE_SESSION, \
                "ACCEPTANCE TEST FAILED: state machine did not reach ACTIVE_SESSION"

            self.logger.info(
                "✓ Acceptance Test 1 PASSED: State Machine → ACTIVE_SESSION"
            )

        else:

            self.logger.info(
                "Challenge Verification Failed — Authentication Denied"
            )

        # ==================================================
        # PHASE 12 : PERFORMANCE REPORT
        # ==================================================

        total_time = (
            time.perf_counter()
            - overall_start
        )

        self.logger.info(
            "\n========================="
        )

        self.logger.info(
            "PERFORMANCE REPORT"
        )

        self.logger.info(
            "========================="
        )

        self.logger.info(
            f"Total Execution Time: {total_time:.6f} sec"
        )

        report = self.metrics.report()

        self.logger.info(
            f"Total CAN Messages: "
            f"{report['total_messages']}"
        )

        self.logger.info(
            f"Total Bytes: "
            f"{report['total_bytes']}"
        )

        self.logger.info(
            f"Average Payload: "
            f"{report['average_payload']:.2f}"
        )

        self.logger.info(
            f"Average Latency: "
            f"{report['average_latency_ms']:.2f} ms"
        )

        self.metrics.export()

        self.logger.info(
            "\nMetrics Exported"
        )
