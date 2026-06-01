import secrets


def generate_nonce(length: int = 32) -> bytes:
    return secrets.token_bytes(length)


def generate_session_id(length: int = 16) -> str:
    return secrets.token_hex(length)
