from attacks.suspension_attack import SuspensionAttack

attack = SuspensionAttack()

result = attack.block(
    "BATTERY_MESSAGE"
)

print(
    "\nResult:",
    result
)

print(
    "\nSUSPENSION ATTACK SUCCESSFULLY SIMULATED"
)