from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature
from crypto.models.certificate_model import Certificate
from datetime import datetime


def create_certificate(
    root_ca,
    battery_id,
    manufacturer_id,
    battery_public_key,
    issue_date,
    expiry_date
):

    certificate_data = (
        battery_id.encode()
        + manufacturer_id.encode()
        + battery_public_key
        + issue_date.encode()
        + expiry_date.encode()
    )

    signature = root_ca.private_key.sign(
        certificate_data,
        ec.ECDSA(hashes.SHA256())
    )

    return Certificate(
        battery_id=battery_id,
        manufacturer_id=manufacturer_id,
        public_key=battery_public_key,
        issue_date=issue_date,
        expiry_date=expiry_date,
        signature=signature
    )


def is_certificate_expired(
    certificate
):

    expiry_date = datetime.strptime(
        certificate.expiry_date,
        "%Y-%m-%d"
    )

    return (
        datetime.now() >
        expiry_date
    )

def verify_certificate(
    certificate,
    manufacturer_public_key
):
    if is_certificate_expired(certificate):
        return False

    certificate_data = (
        certificate.battery_id.encode()
        + certificate.manufacturer_id.encode()
        + certificate.public_key
        + certificate.issue_date.encode()
        + certificate.expiry_date.encode()
    )

    try:
        manufacturer_public_key.verify(
            certificate.signature,
            certificate_data,
            ec.ECDSA(hashes.SHA256())
        )

        return True

    except InvalidSignature:
        return False


        return False

    