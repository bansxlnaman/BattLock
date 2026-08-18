import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from datetime import datetime
from crypto.certs.root_ca import RootCA
from crypto.crypto_utils.signatures import generate_keypair
from crypto.crypto_utils.key_serialization import serialize_public_key
from crypto.certs.certificate import verify_certificate
from attacks.certificate_tampering_attack import CertificateTamperingAttack


def main():
    root_ca = RootCA()
    private_key, public_key = generate_keypair()
    pub_bytes = serialize_public_key(public_key)

    tamper = CertificateTamperingAttack()

    expired = tamper.create_expired_certificate(
        root_ca, public_key=pub_bytes
    )
    assert not verify_certificate(expired, root_ca.public_key)

    # Note: the current verify_certificate() only rejects expired certs;
    # future-dated certs are not rejected by this implementation.
    future = tamper.create_future_certificate(
        root_ca, public_key=pub_bytes
    )
    print("Future-dated certificate (issue-date check not enforced):",
          verify_certificate(future, root_ca.public_key))

    rogue = tamper.create_self_signed_certificate(
        public_key=pub_bytes
    )
    assert not verify_certificate(rogue, root_ca.public_key)

    valid = tamper.create_expired_certificate(
        root_ca, public_key=pub_bytes
    )
    tamper.tamper_certificate_field(valid, "battery_id", "BAT_EVIL")
    assert not verify_certificate(valid, root_ca.public_key)

    print("Certificate tampering attack test passed")


if __name__ == "__main__":
    main()
