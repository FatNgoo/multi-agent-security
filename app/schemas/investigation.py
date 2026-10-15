from datetime import datetime
from typing import Any
from pydantic import BaseModel, Field


class InvestigationRequest(BaseModel):
    host: str = Field(min_length=1, max_length=128)
    dataset_id: str = Field(min_length=36, max_length=36)
    start_time: datetime
    end_time: datetime


class Evidence(BaseModel):
    evidence_id: str
    timestamp: datetime
    host: str
    event_id: int
    description: str
    raw: dict[str, Any]


class InvestigationResponse(BaseModel):
    status: str
    dataset_id: str
    route: str
    mode: str
    host: str
    summary: str
    evidence: list[Evidence]
    tool_trace: list[str]
    warning: str | None = None
