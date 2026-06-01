from dataclasses import dataclass
from datetime import datetime

from crypto.crypto_utils.random_gen import generate_nonce


@dataclass
class Challenge:

    nonce: bytes
    timestamp: int


def create_challenge():

    return Challenge(
        nonce=generate_nonce(), timestamp=int(datetime.utcnow().timestamp())
    )
