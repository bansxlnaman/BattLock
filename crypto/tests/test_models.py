from crypto.models.battery_identity import BatteryIdentity

battery = BatteryIdentity(
    battery_id="BAT001",
    serial_number="SN123456",
    manufacturer_id="THAPAR"
)

print(battery)