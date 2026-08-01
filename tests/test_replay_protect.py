from crypto.counters.replay_protection import (
    ReplayProtection
)


def test_replay():

    replay = ReplayProtection()

    counter = 1

    assert replay.validate(counter)

    assert not replay.validate(counter)

    assert replay.validate(counter + 1)

    print(
        "\n[PASS]"
        " Replay attack blocked"
    )


if __name__ == "__main__":

    test_replay()
