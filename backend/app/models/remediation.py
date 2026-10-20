from typing import Literal

from pydantic import BaseModel, Field


Effort = Literal["low", "medium", "high"]
EvidenceClassification = Literal["observed_finding", "modeled_assumption"]


class RemediationRecommendation(BaseModel):
    id: str
    rank: int = Field(ge=1)
    related_finding_ids: list[str] = Field(default_factory=list)
    finding_title: str
    file_path: str
    severity: str
    confidence: str
    detection_type: str
    recommended_action: str
    rationale: str
    verification_steps: list[str] = Field(default_factory=list)
    estimated_effort: Effort
    risk_reduction_score: int = Field(ge=0, le=100)
    score_explanation: str
    evidence_classification: EvidenceClassification = "observed_finding"
    covered_path_ids: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class PathCoverage(BaseModel):
    modeled_paths: int = Field(ge=0)
    candidate_covered_paths: int = Field(ge=0)
    unaddressed_paths: int = Field(ge=0)
    covered_path_ids: list[str] = Field(default_factory=list)
    unaddressed_path_ids: list[str] = Field(default_factory=list)
    interpretation: str


class RemediationResponse(BaseModel):
    scan_id: str
    budget: int = Field(ge=1, le=25)
    summary: str
    limitations: list[str] = Field(default_factory=list)
    path_coverage_before: PathCoverage
    path_coverage_after: PathCoverage
    optimization_explanation: str
    ranked_recommendations: list[RemediationRecommendation] = Field(
        default_factory=list
    )
    selected_recommendations: list[RemediationRecommendation] = Field(
        default_factory=list
    )
