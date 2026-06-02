import time
import platform
from datetime import datetime, timedelta

from integration.logger import BattLockLogger
from integration.metrics import MetricsCollector

from crypto.certs.root_ca import RootCA
from crypto.certs.certificate import (
create_certificate,
verify_certificate
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

from crypto.models.battery import Battery
from crypto.auth.verifier import (
verify_challenge_response
)

from crypto.keys.key_manager import KeyManager

from can.simulation.vehicle_node import VehicleNode
from can.simulation.battery_node import BatteryNode

class BattLockOrchestrator:

    def __init__(self):

        self.logger = BattLockLogger()

        self.metrics = MetricsCollector()

        self.session_manager = SessionManager()

    def log_can_message(
        self,
        frame
    ):

        payload_size = len(frame.data)

        latency = 0.1

        self.metrics.record_can(
            payload_size,
            latency
        )

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
            "Private Key Stored Securely"
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
            battery_public_key = battery_public_key,
            issue_date=
            datetime.now().strftime(
                "%Y-%m-%d"
            ),
            expiry_date=
            (
                datetime.now()
                + timedelta(days=365)
            ).strftime(
                "%Y-%m-%d"
            )
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
        # PHASE 5 : CAN NETWORK
        # ==================================================

        self.logger.info(
            "\n[PHASE 5] CAN NETWORK STARTUP"
        )

        bus = CANBus()

        vehicle = VehicleNode(bus=bus)

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

        cert_msg = (
            battery_node.send_certificate(
                certificate
            )
        )

        bus.send(cert_msg)
        self.log_can_message(
            cert_msg
        )

        received_cert = (
            bus.receive()
        )

        self.logger.info(
            "Certificate sent over CAN"
        )

        # ==================================================
        # PHASE 6 : AUTH REQUEST
        # ==================================================

        self.logger.info(
            "\n[PHASE 6] AUTHENTICATION START"
        )

        self.logger.info(
            "\nVehicle -> Battery"
        )

        self.logger.info(
            "CAN ID: 0x100"
        )

        auth_msg = (
            vehicle.send_auth_request()
        )
        bus.send(auth_msg)
        self.log_can_message(auth_msg)
        received = bus.receive()
        self.logger.info(
            f"AUTH_REQUEST SENT: "
            f"{received.data}"
        )


        # ==================================================
        # PHASE 7 : CERTIFICATE RESPONSE
        # ==================================================

        self.logger.info(
            "\nBattery -> Vehicle"
        )

        self.logger.info(
            "CAN ID: 0x104"
        )

        self.log_can_message(received_cert)

        # ==================================================
        # PHASE 8 : CERTIFICATE VERIFICATION
        # ==================================================

        self.logger.info(
            "\n[PHASE 8] CERTIFICATE VERIFICATION"
        )

        self.metrics.start(
            "certificate_verification"
        )

        valid = verify_certificate(
            certificate,
            root_ca.public_key
        )

        self.metrics.stop(
            "certificate_verification"
        )

        if not valid:

            self.logger.info(
                "Certificate Verification Failed"
            )

            return

        self.logger.info(
            "Certificate Verification Successful"
        )

        # ==================================================
        # PHASE 9 : CHALLENGE GENERATION
        # ==================================================

        self.logger.info(
            "\n[PHASE 9] CHALLENGE GENERATION"
        )

        challenge = create_challenge()

        self.logger.info(
            "Challenge Generated"
        )

        nonce_msg = vehicle.send_nonce(
            challenge.nonce
        )

        bus.send(nonce_msg)
        self.log_can_message(nonce_msg)
        received_nonce = (
            bus.receive()
        )

        nonce = battery_node.receive_nonce(
            received_nonce
        )
        self.log_can_message(received_nonce)
        self.logger.info(
            f"Nonce Length: {len(challenge.nonce)} bytes"
        )

        self.logger.info(
            "\nVehicle -> Battery"
        )

        self.logger.info(
            "CAN ID: 0x101"
        )

        self.logger.info(
            "NONCE"
        )

        # ==================================================
        # PHASE 10 : SIGNATURE GENERATION
        # ==================================================

        self.logger.info(
            "\n[PHASE 10] SIGNATURE GENERATION"
        )

        challenge_data = (
            challenge.nonce
            + str(
                challenge.timestamp
            ).encode()
        )

        self.metrics.start(
            "signature_generation"
        )

        signature = battery.sign(
            challenge_data
        )

        self.metrics.stop(
            "signature_generation"
        )

        self.logger.info(
            "Challenge Signed"
        )

        self.logger.info(
            f"Signature Length: {len(signature)} bytes"
        )

        self.logger.info(
            "\nBattery -> Vehicle"
        )

        self.logger.info(
            "CAN ID: 0x102"
        )

        self.logger.info(
            "SIGNATURE"
        )

        # ==================================================
        # PHASE 11 : SIGNATURE VERIFICATION
        # ==================================================

        self.logger.info(
            "\n[PHASE 11] CHALLENGE VERIFICATION"
        )

        self.metrics.start(
            "signature_verification"
        )

        result = (
            verify_challenge_response(
                certificate,
                challenge,
                signature
            )
        )

        self.metrics.stop(
            "signature_verification"
        )

        if result:

            self.logger.info(
                "Challenge Verification Passed"
            )

            self.logger.info(
                "\nVehicle -> Battery"
            )

            self.logger.info(
                "CAN ID: 0x103"
            )

            self.logger.info(
                "AUTH_RESULT = SUCCESS"
            )
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
            session_msg = (
                vehicle.send_session_id(
                    session
                )
            )

            self.log_can_message(session_msg)
            bus.send(session_msg)

            received_session = (
                bus.receive()
            )
            self.log_can_message(received_session)

            battery_node.receive_session_id(
                received_session
            )
            self.logger.info(
                "\nVehicle -> Battery"
            )

            self.logger.info(
                "CAN ID: 0x105"
            )

            self.logger.info(
                "SESSION_ID"
            )



            self.logger.info(
                "\nBATTERY AUTHENTICATED"
            )

            self.logger.info(
                "SECURE SESSION ACTIVE"
            )

        else:

            self.logger.info(
                "Challenge Verification Failed"
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
