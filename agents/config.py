from __future__ import annotations

import os
import socket
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv


load_dotenv(Path(__file__).with_name(".env"))


def _required(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"Required environment variable {name} is missing")
    return value


@dataclass(frozen=True)
class ExecutorSettings:
    db_host: str
    db_port: int
    db_user: str
    db_password: str
    db_name: str
    poll_seconds: int
    approval_ttl_seconds: int
    lease_seconds: int
    max_output_bytes: int
    executor_id: str

    @classmethod
    def from_environment(cls) -> "ExecutorSettings":
        poll_seconds = int(os.getenv("EXECUTOR_POLL_SECONDS", "3"))
        approval_ttl_seconds = int(
            os.getenv("EXECUTOR_APPROVAL_TTL_SECONDS", "900")
        )
        lease_seconds = int(os.getenv("EXECUTOR_LEASE_SECONDS", "900"))
        max_output_bytes = int(os.getenv("EXECUTOR_MAX_OUTPUT_BYTES", "262144"))
        if poll_seconds < 1:
            raise RuntimeError("EXECUTOR_POLL_SECONDS must be at least 1")
        if approval_ttl_seconds < 60:
            raise RuntimeError(
                "EXECUTOR_APPROVAL_TTL_SECONDS must be at least 60"
            )
        if lease_seconds < 120:
            raise RuntimeError("EXECUTOR_LEASE_SECONDS must be at least 120")
        if max_output_bytes < 4096:
            raise RuntimeError("EXECUTOR_MAX_OUTPUT_BYTES must be at least 4096")

        return cls(
            db_host=_required("DB_HOST"),
            db_port=int(os.getenv("DB_PORT", "3306")),
            db_user=_required("DB_USER"),
            db_password=_required("DB_PASSWORD"),
            db_name=_required("DB_NAME"),
            poll_seconds=poll_seconds,
            approval_ttl_seconds=approval_ttl_seconds,
            lease_seconds=lease_seconds,
            max_output_bytes=max_output_bytes,
            executor_id=os.getenv(
                "EXECUTOR_ID",
                f"{socket.gethostname()}:{os.getpid()}",
            ),
        )
