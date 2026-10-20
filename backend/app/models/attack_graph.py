from typing import Literal

from pydantic import BaseModel, Field


NodeType = Literal[
    "component", "dependency", "finding", "asset", "entry_point"
]
EdgeType = Literal[
    "contains", "depends_on", "has_finding", "may_reach", "exposes"
]
RiskLevel = Literal[
    "critical", "high", "medium", "low", "info", "unknown"
]
EvidenceType = Literal["observed", "modeled"]


class AttackGraphNode(BaseModel):
    id: str
    label: str
    node_type: NodeType
    description: str = ""
    risk_level: RiskLevel = "unknown"
    evidence_type: EvidenceType = "modeled"


class AttackGraphEdge(BaseModel):
    source: str
    target: str
    edge_type: EdgeType
    description: str = ""
    evidence_type: EvidenceType = "modeled"


class AttackPath(BaseModel):
    id: str
    title: str
    node_ids: list[str] = Field(default_factory=list)
    risk_level: RiskLevel = "unknown"
    explanation: str
    evidence_type: EvidenceType = "modeled"


class AttackGraphResponse(BaseModel):
    scan_id: str
    nodes: list[AttackGraphNode] = Field(default_factory=list)
    edges: list[AttackGraphEdge] = Field(default_factory=list)
    attack_paths: list[AttackPath] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
