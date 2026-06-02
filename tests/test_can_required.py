from can.transport import CANBus

from integration.orchestrator import (
    BattLockOrchestrator
)


def test_can_required():

    original_send = CANBus.send

    try:

        def broken_send(
            self,
            message
        ):
            pass

        CANBus.send = broken_send

        system = (
            BattLockOrchestrator()
        )

        system.run()

        print(
            "\n[FAIL]"
            " Authentication succeeded"
            " with CAN disabled"
        )

    except Exception:

        print(
            "\n[PASS]"
            " Authentication fails"
            " when CAN is disabled"
        )

    finally:

        CANBus.send = original_send


if __name__ == "__main__":

    test_can_required()