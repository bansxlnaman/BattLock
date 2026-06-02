from dataclasses import dataclass

@dataclass
class BatteryStatus:

    counter: int

    voltage: float
    current: float
    temperature: float

    soc: int
    soh: int

    fault_flags: int