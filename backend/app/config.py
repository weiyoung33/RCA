from __future__ import annotations

import os
from dataclasses import dataclass

from dotenv import load_dotenv


load_dotenv()


def required_env(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"Required environment variable {name} is missing")
    return value


@dataclass(frozen=True)
class Settings:
    db_host: str
    db_port: int
    db_user: str
    db_password: str
    db_name: str
    cors_origins: tuple[str, ...]
    dev_user_name: str
    dev_user_role: str
    enable_test_injection: bool
    allowed_link_emails: frozenset[str]

    @classmethod
    def from_environment(cls) -> "Settings":
        origins = tuple(
            origin.strip()
            for origin in os.getenv("CORS_ORIGINS", "http://localhost:5173").split(",")
            if origin.strip()
        )
        allowed_link_emails = frozenset(
            email.strip().casefold()
            for email in os.getenv("RCA_ALLOWED_LINK_EMAILS", "").split(",")
            if email.strip()
        )
        return cls(
            db_host=required_env("DB_HOST"),
            db_port=int(os.getenv("DB_PORT", "3306")),
            db_user=required_env("DB_USER"),
            db_password=required_env("DB_PASSWORD"),
            db_name=required_env("DB_NAME"),
            cors_origins=origins,
            dev_user_name=os.getenv("DEV_USER_NAME", "Prototype Engineer"),
            dev_user_role=os.getenv("DEV_USER_ROLE", "engineer"),
            enable_test_injection=os.getenv(
                "ENABLE_TEST_INJECTION", "false"
            ).strip().lower() in {"1", "true", "yes", "on"},
            allowed_link_emails=allowed_link_emails,
        )


settings = Settings.from_environment()
