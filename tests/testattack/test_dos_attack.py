from attacks.dos_attack import DoSAttack

attack = DoSAttack()

messages = attack.flood()

print(
    "\nTotal Messages:",
    len(messages)
)

print(
    "\nDOS ATTACK SUCCESSFULLY SIMULATED"
)