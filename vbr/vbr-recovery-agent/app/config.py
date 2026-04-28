import json
from typing import Any, Optional

from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # Veeam
    VEEAM_URL: str
    VEEAM_USERNAME: str
    VEEAM_PASSWORD: str
    VEEAM_VERIFY_SSL: bool = True
    VEEAM_API_VERSION: str = "1.3-rev1"

    # Recovery policy
    CONFIRMATION_TTL_MINUTES: int = 30
    RESTORE_CONFIDENCE_THRESHOLD: int = 70          # minimum score for a restore point to be considered safe
    PREFERRED_REPOSITORIES: list[str] = []          # repo names that receive a score bonus; JSON array or comma-separated

    @field_validator("PREFERRED_REPOSITORIES", mode="before")
    @classmethod
    def _parse_repo_list(cls, v: Any) -> list[str]:
        if isinstance(v, str):
            try:
                return json.loads(v)
            except (json.JSONDecodeError, ValueError):
                return [r.strip() for r in v.split(",") if r.strip()]
        return v or []

    # New Relic
    NR_ACCOUNT_ID: str
    NR_LICENSE_KEY: str
    # EU: insights-collector.eu01.nr-data.net  |  US: insights-collector.newrelic.com
    NR_EVENTS_ENDPOINT: str = "https://insights-collector.eu01.nr-data.net/v1/accounts/{account_id}/events"
    NR_WEBHOOK_SECRET: Optional[str] = None    # optional — verify incoming NR webhook
    AGENT_API_KEY: Optional[str] = None        # optional — protect operator endpoints

    # Local/dev only. Production should require both shared secrets.
    ALLOW_UNAUTHENTICATED_DEV: bool = False

    # Service
    LOG_LEVEL: str = "INFO"

    @model_validator(mode="after")
    def _require_secrets_unless_dev(self) -> "Settings":
        missing = [
            name for name, value in (
                ("NR_WEBHOOK_SECRET", self.NR_WEBHOOK_SECRET),
                ("AGENT_API_KEY", self.AGENT_API_KEY),
            )
            if not value or not value.strip()
        ]
        if missing and not self.ALLOW_UNAUTHENTICATED_DEV:
            raise ValueError(
                "Missing required security settings: "
                + ", ".join(missing)
                + ". Set ALLOW_UNAUTHENTICATED_DEV=true only for local development."
            )
        return self

    class Config:
        env_file = ".env"


settings = Settings()
