from attacks.injection_attack import InjectionAttack

attack = InjectionAttack()

message = attack.inject_fake_status()

print("\nInjected Message:")
print(message)

print(
    "\nINJECTION ATTACK SUCCESSFULLY SIMULATED"
)