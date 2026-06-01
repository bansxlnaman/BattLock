class ATECC608:

    def __init__(self):

        self.connected = False

    def connect(self):

        self.connected = True

    def sign(self, data: bytes):

        raise NotImplementedError("ATECC608 hardware integration pending")

    def get_public_key(self):

        raise NotImplementedError("ATECC608 hardware integration pending")
