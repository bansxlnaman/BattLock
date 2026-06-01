class MessageCounter:

    def __init__(self):

        self.counter = 0

    def next(self):

        self.counter += 1

        return self.counter

    def current(self):

        return self.counter

    def reset(self):

        self.counter = 0