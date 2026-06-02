import pickle

from protocol.messages.battery_hello import BatteryHello

from protocol.messages.auth_challenge import AuthChallenge

from protocol.messages.auth_response import AuthResponse

from protocol.messages.auth_success import AuthSuccess

from protocol.messages.telemetry import Telemetry

from performance.crypto.csv_utils import update_metric


def size_of(message):

    return len(pickle.dumps(message))


def benchmark():

    hello = BatteryHello(certificate=None)

    challenge = AuthChallenge(nonce=b"1234567890", timestamp=123456)

    response = AuthResponse(signature=b"x" * 64)

    success = AuthSuccess(session_id="SESSION123")

    telemetry = Telemetry(
        session_id="SESSION123",
        counter=1,
        voltage=51.2,
        current=10.5,
        temperature=30.0,
        soc=85.0,
        soh=98.0,
        fault_flags=0,
    )

    print("\n=== MESSAGE SIZE BENCHMARK ===")

    update_metric("batteryhello_size", size_of(hello), "bytes")

    update_metric("authchallenge_size", size_of(challenge), "bytes")

    update_metric("authresponse_size", size_of(response), "bytes")

    update_metric("authsuccess_size", size_of(success), "bytes")

    update_metric("telemetry_size", size_of(telemetry), "bytes")


if __name__ == "__main__":
    benchmark()
