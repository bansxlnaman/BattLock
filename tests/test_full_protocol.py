from integration.orchestrator import (
    BattLockOrchestrator
)


def test_full_protocol():

    system = BattLockOrchestrator()

    try:

        system.run()

        print(
            "\n[PASS] Full protocol completed"
        )

    except Exception as e:

        print(
            "\n[FAIL] Protocol failed"
        )

        raise e


if __name__ == "__main__":

    test_full_protocol()