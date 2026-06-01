from dataclasses import dataclass

from crypto.crypto_utils.random_gen import generate_session_id


@dataclass
class Session:

    session_id: str
    battery_id: str


def create_session(battery_id):

    return Session(session_id=generate_session_id(), battery_id=battery_id)
