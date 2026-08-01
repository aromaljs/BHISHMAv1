from dataclasses import dataclass, asdict, field
from typing import List, Dict, Any


@dataclass
class Service:
    port: int
    protocol: str
    state: str
    service: str
    vendor: str
    product: str
    version: str
    cpe: str
    confidence: int
    quality: str
    os_hint: str
    evidence: str
    reason: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Asset:
    target: str
    hostname: str = "Unknown"
    os_guess: str = "Unknown"
    services: List[Service] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "hostname": self.hostname,
            "os_guess": self.os_guess,
            "services": [s.to_dict() for s in self.services],
        }
