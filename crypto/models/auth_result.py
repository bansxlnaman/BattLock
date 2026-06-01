from dataclasses import dataclass


@dataclass
class AuthResult:
    """
    Result of authentication process.
    """

    success: bool
    session_id: str
    reason: str