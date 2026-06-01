from protocol.state_machine import (
    BattLockStateMachine
)


sm = BattLockStateMachine()

print(sm.get_state())

sm.hello_received()

print(sm.get_state())

sm.certificate_verified()

print(sm.get_state())

sm.challenge_sent()

print(sm.get_state())

sm.authenticated()

print(sm.get_state())

sm.session_established()

print(sm.get_state())

print(sm.telemetry_allowed())