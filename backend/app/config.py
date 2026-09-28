"""Environment-backed application configuration."""

from dataclasses import dataclass
import os


@dataclass(frozen=True)
class Settings:
    application_name: str = "IncidentForge API"
    environment: str = "development"
    api_host: str = "127.0.0.1"
    api_port: int = 8000
    log_level: str = "INFO"
    database_url: str = "sqlite:///backend/data/incidentforge.db"
    cors_origins: str = "http://localhost:3000,http://127.0.0.1:3000"
    hindsight_enabled: bool = False
    hindsight_endpoint: str = "http://127.0.0.1:8888"
    hindsight_timeout_seconds: float = 2.0
    hindsight_max_memories: int = 5
    hindsight_failure_threshold: int = 3
    hindsight_cooldown_seconds: float = 30.0


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def get_settings() -> Settings:
    """Load non-secret settings from the process environment."""
    return Settings(
        application_name=os.getenv("INCIDENTFORGE_APP_NAME", Settings.application_name),
        environment=os.getenv("INCIDENTFORGE_ENVIRONMENT", Settings.environment),
        api_host=os.getenv("INCIDENTFORGE_API_HOST", Settings.api_host),
        api_port=int(os.getenv("INCIDENTFORGE_API_PORT", str(Settings.api_port))),
        log_level=os.getenv("INCIDENTFORGE_LOG_LEVEL", Settings.log_level).upper(),
        database_url=os.getenv("INCIDENTFORGE_DATABASE_URL", Settings.database_url),
        cors_origins=os.getenv("INCIDENTFORGE_CORS_ORIGINS", Settings.cors_origins),
        hindsight_enabled=_env_bool("HINDSIGHT_ENABLED", Settings.hindsight_enabled),
        hindsight_endpoint=os.getenv("HINDSIGHT_ENDPOINT", Settings.hindsight_endpoint).rstrip("/"),
        hindsight_timeout_seconds=float(
            os.getenv("HINDSIGHT_TIMEOUT_SECONDS", str(Settings.hindsight_timeout_seconds))
        ),
        hindsight_max_memories=int(os.getenv("HINDSIGHT_MAX_MEMORIES", str(Settings.hindsight_max_memories))),
        hindsight_failure_threshold=int(
            os.getenv("HINDSIGHT_FAILURE_THRESHOLD", str(Settings.hindsight_failure_threshold))
        ),
        hindsight_cooldown_seconds=float(
            os.getenv("HINDSIGHT_COOLDOWN_SECONDS", str(Settings.hindsight_cooldown_seconds))
        ),
    )
