from attacks.replay_attack import ReplayAttack
from can.can_message import CANMessage


attack = ReplayAttack()

# Create a dummy CAN message
message = CANMessage(
    arbitration_id=0x100,
    data=b"BAT001"
)

# Capture the message
attack.capture(message)

# Replay it
replayed_message = attack.replay()

print("Original Message:")
print(message)

print("\nReplayed Message:")
print(replayed_message)

# Check if replay worked
if replayed_message == message:
    print("\nREPLAY ATTACK SUCCESSFULLY SIMULATED")
else:
    print("\nTEST FAILED")