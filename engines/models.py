from dataclasses import dataclass, asdict
from typing import Optional


@dataclass
class Finding:
    port: int
    service: str
    version: str
    fingerprint_confidence: int
    fingerprint_quality: str
    finding_type: str
    cve_status: str
    cve: Optional[str]
    title: str
    severity: str
    confidence: str
    cvss: float
    evidence: str
    description: str
    remediation: str
    verification: str = "not_run"

    def to_dict(self):
        return asdict(self)
