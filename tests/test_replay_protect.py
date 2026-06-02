from crypto.counters.replay_protection import (
    ReplayProtection
)


def test_replay():

    replay = ReplayProtection()

    counter = 1

    assert replay.is_valid(counter)

    replay.update(counter)

    assert not replay.is_valid(counter)

    print(
        "\n[PASS]"
        " Replay attack blocked"
    )


if __name__ == "__main__":

    test_replay()