from crypto.counters.replay_protection import (
    ReplayProtection
)


guard = ReplayProtection()

print(
    guard.validate(1)
)

print(
    guard.validate(2)
)

print(
    guard.validate(3)
)

print(
    guard.validate(2)
)