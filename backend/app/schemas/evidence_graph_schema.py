from pydantic import BaseModel, Field


class EvidenceGraphNode(BaseModel):
    id: str
    type: str
    label: str
    safe_summary: str | None = None
    role: str | None = None
    masked_value: str | None = None
    confidence_band: str | None = None


class EvidenceGraphEdge(BaseModel):
    source: str
    target: str
    relationship: str
    # Phase O: typed causal-graph fields. Wording is always
    # supports/correlates — never "proved caused by".
    relationship_type: str = "RELATED_TO"
    strength: float = Field(default=0.4, ge=0, le=1)
    relationship_reason: str = "Related evidence item."
    correlation_rule_id: str | None = None


class EvidenceGraphResponse(BaseModel):
    incident_id: str
    nodes: list[EvidenceGraphNode] = Field(default_factory=list)
    edges: list[EvidenceGraphEdge] = Field(default_factory=list)
    disclaimer: str
