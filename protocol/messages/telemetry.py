from dataclasses import dataclass


@dataclass
class Telemetry:

    session_id: str

    counter: int

    voltage: float
    current: float

    temperature: float

    soc: float
    soh: float

    fault_flags: int