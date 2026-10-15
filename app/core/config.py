from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    agent_mode: str = "offline"
    gemini_api_key: str = ""
    gemini_model: str = "gemini-2.5-flash"
    gemini_base_url: str = "https://generativelanguage.googleapis.com/v1beta/openai/"
    deepseek_api_key: str = ""
    deepseek_model: str = "deepseek-chat"
    deepseek_base_url: str = "https://api.deepseek.com"
    database_url: str = "sqlite:///./local-dev.db"
    max_upload_bytes: int = 5_000_000
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


settings = Settings()
