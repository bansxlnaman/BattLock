from can.transport import CANBus

bus = CANBus()

bus.send("Hello")

print(bus.receive())