from dataclasses import dataclass


@dataclass
class AuthChallenge:

    nonce: bytes
    timestamp: int