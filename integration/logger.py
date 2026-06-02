import logging
import os

class BattLockLogger:

    def __init__(self):

        os.makedirs("logs", exist_ok=True)

        logging.basicConfig(
            filename="logs/battlock.log",
            level=logging.INFO,
            format="%(asctime)s | %(message)s"
        )

    def info(self, message):

        print(message)

        logging.info(message)