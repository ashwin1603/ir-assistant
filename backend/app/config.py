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
    ollama_timeout_seconds: int = 35
    ollama_num_predict: int = 150
    ollama_num_ctx: int = 2048
    ollama_keep_alive: str = "30m"

    ai_calls_per_hour: int = 20

    admin_username: str = ""
    admin_password: str = ""

    rate_limit_enabled: bool = True

    # Live-update stream (GET /api/stream): poll interval and maximum stream lifetime.
    stream_poll_seconds: float = 5
    stream_max_seconds: int = 60

    upload_dir: str = "uploads"  # outside any served directory; git-ignored
    upload_max_mb: int = 20

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")


settings = Settings()
