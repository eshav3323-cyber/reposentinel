
from typing import Literal

from pydantic import BaseModel, Field


Severity = Literal["critical", "high", "medium", "low", "info"]
DetectionType = Literal["scanner", "heuristic", "modeled_assumption"]
Confidence = Literal["high", "medium", "low"]


class FindingExplanation(BaseModel):
    simple_title: str
    what_it_means: str
    why_it_matters: str
    possible_impact: list[str]
    how_to_fix: list[str]


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
    explanation: FindingExplanation | None = None
