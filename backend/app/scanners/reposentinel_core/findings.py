from dataclasses import asdict, dataclass
from typing import Any


@dataclass
class SecurityFinding:
    rule_id: str
    title: str
    description: str
    severity: str
    confidence: str
    cwe: str
    file_path: str
    line_number: int
    language: str
    evidence: str
    recommendation: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)