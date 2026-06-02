class ReplayAttack:

    def __init__(self):

        self.saved_message = None

    def capture(self, message):

        self.saved_message = message

    def replay(self):

        return self.saved_message