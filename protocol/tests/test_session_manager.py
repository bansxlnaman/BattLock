from protocol.session_manager import (
    SessionManager
)


manager = SessionManager()

manager.add_session(
    "ABC123",
    "BAT001"
)

print(
    manager.session_exists(
        "ABC123"
    )
)

print(
    manager.get_battery(
        "ABC123"
    )
)