
from typing import Literal

from pydantic import BaseModel, Field


Severity = Literal["critical", "high", "medium", "low", "info"]
DetectionType = Literal["scanner", "heuristic", "modeled_assumption"]
Confidence = Literal["high", "medium", "low"]


class Finding(BaseModel):
    id: str
    title: str
    rule_id: str
    severity: Severity
    file_path: str
    line_number: int = Field(ge=1)
    description: str
    redacted_evidence: str
    remediation: str
    source_scanner: str
    confidence: Confidence
    detection_type: DetectionType
