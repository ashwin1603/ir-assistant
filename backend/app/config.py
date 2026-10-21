from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_env: str = "development"
    database_url: str = "sqlite:///./ir_assistant.db"

    jwt_secret: str = "changeme"
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 30

    collector_api_key: str = "changeme"

    cors_origin: str = "http://localhost:5173"

    llm_provider: str = "template"  # "ollama" (local, free) or "template" (deterministic, no network)
    llm_model: str = "qwen2.5:3b"

    ollama_base_url: str = "http://localhost:11434"
    ollama_timeout_seconds: int = 120

    ai_calls_per_hour: int = 20

    admin_username: str = ""
    admin_password: str = ""

    rate_limit_enabled: bool = True

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")


settings = Settings()
