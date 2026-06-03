from attacks.spoofing_attack import SpoofingAttack

attack = SpoofingAttack()

message = attack.create_fake_identity()

print("\nGenerated Message:")
print(message)

print("\nSPOOFING ATTACK SUCCESSFULLY SIMULATED")