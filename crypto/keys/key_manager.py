from crypto.keys.software_keys import (
    SoftwareKeys
)

from crypto.keys.atecc608 import (
    ATECC608
)


class KeyManager:

    def __init__(
        self,
        use_hardware=False
    ):

        if use_hardware:

            self.provider = (
                ATECC608()
            )

        else:

            self.provider = (
                SoftwareKeys()
            )

    def sign(
        self,
        data
    ):

        return self.provider.sign(
            data
        )

    def get_public_key(self):

        return self.provider.get_public_key()