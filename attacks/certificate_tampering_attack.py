from datetime import datetime, timedelta

from crypto.models.certificate_model import Certificate
from crypto.certs.certificate import create_certificate


class CertificateTamperingAttack:
    """
    Certificate-level attacks.

    The attacker creates a certificate that looks legitimate but is either
    expired, self-signed, or has tampered fields.  The vehicle's certificate
    verification must reject all of these.
    """

    def __init__(self):
        self.self_signed_ca = None

    def create_expired_certificate(self, root_ca, battery_id="BAT001",
                                    manufacturer_id="TESLA", public_key=b""):
        """Issue a certificate whose expiry date is in the past."""
        yesterday = (datetime.utcnow() - timedelta(days=1)).strftime("%Y-%m-%d")
        last_year = (datetime.utcnow() - timedelta(days=365)).strftime("%Y-%m-%d")

        cert = create_certificate(
            root_ca=root_ca,
            battery_id=battery_id,
            manufacturer_id=manufacturer_id,
            battery_public_key=public_key,
            issue_date=last_year,
            expiry_date=yesterday
        )
        print("CertificateTamperingAttack: created EXPIRED certificate")
        return cert

    def create_future_certificate(self, root_ca, battery_id="BAT001",
                                   manufacturer_id="TESLA", public_key=b""):
        """Issue a certificate whose issue date is in the future."""
        tomorrow = (datetime.utcnow() + timedelta(days=1)).strftime("%Y-%m-%d")
        next_year = (datetime.utcnow() + timedelta(days=365)).strftime("%Y-%m-%d")

        cert = create_certificate(
            root_ca=root_ca,
            battery_id=battery_id,
            manufacturer_id=manufacturer_id,
            battery_public_key=public_key,
            issue_date=tomorrow,
            expiry_date=next_year
        )
        print("CertificateTamperingAttack: created FUTURE-dated certificate")
        return cert

    def create_self_signed_certificate(self, battery_id="BAT001",
                                        manufacturer_id="TESLA", public_key=b""):
        """
        Create a certificate signed by a brand-new, untrusted Root CA that
        the attacker just generated.  Simulates a rogue manufacturer cert.
        """
        from crypto.certs.root_ca import RootCA
        rogue_ca = RootCA()

        cert = create_certificate(
            root_ca=rogue_ca,
            battery_id=battery_id,
            manufacturer_id=manufacturer_id,
            battery_public_key=public_key,
            issue_date="2026-01-01",
            expiry_date="2031-01-01"
        )
        print("CertificateTamperingAttack: created SELF-SIGNED/ROGUE certificate")
        return cert

    def tamper_certificate_field(self, certificate, field_name, new_value):
        """
        Modify a field of an otherwise valid certificate in-place.
        The signature will no longer match the contents.
        """
        if field_name == "battery_id":
            certificate.battery_id = new_value
        elif field_name == "manufacturer_id":
            certificate.manufacturer_id = new_value
        elif field_name == "issue_date":
            certificate.issue_date = new_value
        elif field_name == "expiry_date":
            certificate.expiry_date = new_value
        elif field_name == "public_key":
            certificate.public_key = new_value
        else:
            raise ValueError(f"Unknown certificate field: {field_name}")

        print(
            "CertificateTamperingAttack: tampered field",
            field_name,
            "->",
            new_value
        )
        return certificate
