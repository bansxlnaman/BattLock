from crypto.crypto_utils.signatures import (
    generate_keypair,
    sign_message,
    verify_signature,
)


def run_test():

    private_key, public_key = generate_keypair()

    message = b"BattLock Authentication"

    signature = sign_message(private_key, message)

    result = verify_signature(public_key, message, signature)

    print("Signature Valid:", result)


if __name__ == "__main__":
    run_test()
