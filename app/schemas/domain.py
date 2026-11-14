from typing import Literal
from pydantic import BaseModel, Field

Severity = Literal["unknown", "informational", "low", "medium", "high", "critical"]
Confidence = Literal["low", "medium", "high"]


class Assessment(BaseModel):
    """LLM narrative stays a reviewable hypothesis with validated references."""
    text: str = Field(max_length=4000)
    evidence_ids: list[str] = Field(max_length=30)
    limitations: list[str] = Field(default_factory=list, max_length=10)


class AlertUpdate(BaseModel):
    status: Literal["new", "acknowledged", "investigating", "closed"]
    note: str = Field(min_length=1, max_length=1000)
    actor: str = Field(default="local analyst", min_length=1, max_length=100)


class ReviewUpdate(BaseModel):
    severity: Severity | None = None
    recommendation_id: str | None = None
    recommendation_status: Literal["pending", "in_progress", "completed", "skipped"] | None = None
    note: str = Field(min_length=1, max_length=1000)
    actor: str = Field(default="local analyst", min_length=1, max_length=100)
