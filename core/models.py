from dataclasses import dataclass, asdict, field
from typing import List, Dict, Any, Optional


@dataclass
class Evidence:
    source: str
    value: str
    confidence: int = 50

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Service:
    port: int
    protocol: str = "tcp"
    state: str = "open"

    service_name: str = "Unknown Service"
    vendor: str = "Unknown"
    product: str = "unknown"
    version: str = "Unknown"
    cpe: str = "Unknown"
    os_hint: str = "Unknown"

    fingerprint_confidence: int = 0
    fingerprint_quality: str = "UNKNOWN"

    evidence: List[Evidence] = field(default_factory=list)

    cve_status: str = "NOT_CHECKED"
    exposure_level: str = "UNKNOWN"
    risk_score: int = 0

    findings: List[Dict[str, Any]] = field(default_factory=list)
    verification: List[Dict[str, Any]] = field(default_factory=list)

    def add_evidence(self, source: str, value: str, confidence: int = 50):
        self.evidence.append(Evidence(source, value, confidence))

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["evidence"] = [e.to_dict() for e in self.evidence]
        return data


@dataclass
class TargetAsset:
    target: str
    hostname: str = "Unknown"
    os_guess: str = "Unknown"

    services: List[Service] = field(default_factory=list)

    overall_risk_score: int = 0
    attack_surface_score: int = 0
    summary: Dict[str, Any] = field(default_factory=dict)

    def add_service(self, service: Service):
        self.services.append(service)

    def get_service_by_port(self, port: int) -> Optional[Service]:
        for service in self.services:
            if service.port == port:
                return service
        return None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "hostname": self.hostname,
            "os_guess": self.os_guess,
            "services": [s.to_dict() for s in self.services],
            "overall_risk_score": self.overall_risk_score,
            "attack_surface_score": self.attack_surface_score,
            "summary": self.summary,
        }
