class CANBus:

    def __init__(self):
        self.queue = []

    def send(self, message):
        self.queue.append(message)

    def receive(self):

        if len(self.queue) == 0:
            return None

        return self.queue.pop(0)