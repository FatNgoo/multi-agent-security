from datetime import datetime
from typing import Any
from typing import Literal
from uuid import UUID
from pydantic import AwareDatetime, BaseModel, Field, IPvAnyAddress, model_validator, field_validator


class HostMapping(BaseModel):
    host: str = Field(min_length=1, max_length=128)
    ip: IPvAnyAddress
    start_time: AwareDatetime
    end_time: AwareDatetime

    @model_validator(mode="after")
    def validate_interval(self):
        if self.start_time > self.end_time:
            raise ValueError("mapping start_time must precede end_time")
        return self


class InvestigationRequest(BaseModel):
    host: str | None = Field(default=None, min_length=1, max_length=128)
    ip: IPvAnyAddress | None = None
    dataset_id: str | None = None
    dataset_ids: list[str] = Field(default_factory=list, max_length=20)
    start_time: AwareDatetime
    end_time: AwareDatetime
    host_mappings: list[HostMapping] = Field(default_factory=list, max_length=100)
    benign_destinations: list[IPvAnyAddress] = Field(default_factory=list, max_length=100)
    asset_criticality: Literal["low", "medium", "high"] = "medium"
    strategy: Literal["heuristic", "single_agent", "multi_agent"] = "multi_agent"
    mode: Literal["offline", "gemini", "deepseek"] | None = None

    @field_validator("dataset_id")
    @classmethod
    def valid_dataset_id(cls, value):
        return str(UUID(value)) if value else None

    @field_validator("dataset_ids")
    @classmethod
    def valid_dataset_ids(cls, values):
        return [str(UUID(value)) for value in values]

    @model_validator(mode="after")
    def validate_scope(self):
        self.dataset_ids = list(dict.fromkeys(([self.dataset_id] if self.dataset_id else []) + self.dataset_ids))
        if not self.dataset_ids or len(self.dataset_ids) > 20:
            raise ValueError("Select between 1 and 20 datasets")
        if self.start_time > self.end_time:
            raise ValueError("start_time must precede end_time")
        return self


class Evidence(BaseModel):
    evidence_id: str
    timestamp: datetime
    host: str
    event_id: int
    description: str
    raw: dict[str, Any]
    source: str = "sysmon"
    dataset_id: str
    normalized: dict[str, Any] = Field(default_factory=dict)
    record_index: int


class InvestigationResponse(BaseModel):
    investigation_id: str
    status: str
    dataset_id: str
    route: str
    mode: str
    host: str | None
    summary: str
    evidence: list[Evidence]
    tool_trace: list[str]
    warning: str | None = None
    dataset_ids: list[str]
    scope: dict[str, Any]
    strategy: str
    findings: list[dict[str, Any]]
    relationships: list[dict[str, Any]]
    risk: dict[str, Any]
    assessments: list[dict[str, Any]]
    process_tree: list[dict[str, Any]]
    plan: list[str]
    coverage: dict[str, Any]
    verification: dict[str, Any]
    timeline: list[dict[str, Any]]
    warnings: list[str]
    timings: dict[str, Any]
    response_plan: dict[str, Any] | None = None
