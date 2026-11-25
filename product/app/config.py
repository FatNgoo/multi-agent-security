from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field
from typing import Literal
from pathlib import Path


class Settings(BaseSettings):
    deployment_environment: Literal["product", "verification", "development"] = "development"
    agent_mode: str = "offline"
    gemini_api_key: str = ""
    gemini_model: str = "gemini-2.5-flash"
    gemini_base_url: str = "https://generativelanguage.googleapis.com/v1beta/openai/"
    deepseek_api_key: str = ""
    deepseek_model: str = "deepseek-chat"
    deepseek_base_url: str = "https://api.deepseek.com"
    database_url: str = "sqlite:///./local-dev.db"
    max_upload_bytes: int = 5_000_000
    max_windows_upload_bytes: int = Field(default=100 * 1024 * 1024, gt=0)
    max_records: int = Field(default=1000, ge=10, le=20000)
    max_tool_calls: int = Field(default=16, ge=3, le=100)
    max_agent_iterations: int = Field(default=2, ge=1, le=8)
    llm_timeout_seconds: float = Field(default=90, gt=0, le=120)
    llm_max_retries: int = Field(default=1, ge=0, le=2)
    gemini_reasoning_effort: Literal["minimal", "low", "medium", "high"] = "low"
    max_output_tokens: int = Field(default=3000, ge=128, le=8000)
    investigation_timeout_seconds: int = Field(default=600, ge=10, le=900)
    max_concurrent_jobs: int = Field(default=2, ge=1, le=8)
    worker_enabled: bool = True
    lease_seconds: int = Field(default=60, ge=15, le=300)
    alert_min_severity: Literal["informational", "low", "medium", "high", "critical"] = "medium"
    alert_min_confidence: Literal["low", "medium", "high"] = "low"
    max_llm_calls: int = Field(default=9, ge=1, le=30)
    max_llm_tokens: int = Field(default=30000, ge=1000, le=100000)
    beacon_min_connections: int = Field(default=6, ge=4, le=100)
    beacon_max_cv: float = Field(default=0.15, ge=0, le=1)
    max_pending_jobs: int = Field(default=100, ge=1, le=1000)
    model_config = SettingsConfigDict(env_file=Path(__file__).resolve().parents[1] / ".env", extra="ignore")


settings = Settings()
