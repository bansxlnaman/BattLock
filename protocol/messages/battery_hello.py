from dataclasses import dataclass

from crypto.models.certificate_model import Certificate


@dataclass
class BatteryHello:

    certificate: Certificate
