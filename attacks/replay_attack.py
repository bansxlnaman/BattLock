class ReplayAttack:

    def __init__(self):

        self.captured_message = None

    def capture(self, message):

        self.captured_message = message

        print(
            "Captured:",
            message
        )

    def replay(self):

        print(
            "Replaying:",
            self.captured_message
        )

        return self.captured_message