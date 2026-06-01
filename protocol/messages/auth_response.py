from dataclasses import dataclass


@dataclass
class AuthResponse:

    signature: bytes
