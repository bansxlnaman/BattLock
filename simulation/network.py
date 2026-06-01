class Network:

    def send(
        self,
        sender,
        receiver,
        message
    ):

        print(
            f"[{sender}] -> [{receiver}] : "
            f"{type(message).__name__}"
        )

        return message