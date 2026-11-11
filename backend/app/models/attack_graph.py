from typing import Literal

from pydantic import BaseModel, Field, model_validator


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

    @model_validator(mode="after")
    def validate_references(self) -> "AttackGraphResponse":
        node_ids = [node.id for node in self.nodes]
        known_node_ids = set(node_ids)
        if len(known_node_ids) != len(node_ids):
            raise ValueError("Attack graph node IDs must be unique.")

        for edge in self.edges:
            if edge.source not in known_node_ids or edge.target not in known_node_ids:
                raise ValueError("Attack graph edges must reference existing nodes.")

        path_ids: set[str] = set()
        for path in self.attack_paths:
            if path.id in path_ids:
                raise ValueError("Attack graph path IDs must be unique.")
            path_ids.add(path.id)
            if len(path.node_ids) != len(set(path.node_ids)):
                raise ValueError("Attack graph paths must not repeat node IDs.")
            if any(node_id not in known_node_ids for node_id in path.node_ids):
                raise ValueError("Attack graph paths must reference existing nodes.")

        return self
