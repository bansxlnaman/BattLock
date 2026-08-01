import logging
import os
import sys

def _configure_utf8_stdout():
    """Force UTF-8 output on Windows consoles that default to cp1252."""
    try:
        if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
            sys.stdout.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass

_configure_utf8_stdout()


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