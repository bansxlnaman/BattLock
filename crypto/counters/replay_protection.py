class ReplayProtection:

    def __init__(self):

        self.last_counter = 0

    def validate(self, received_counter: int) -> bool:

        if received_counter <= self.last_counter:
            return False

        self.last_counter = received_counter

        return True
