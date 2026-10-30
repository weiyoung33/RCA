from __future__ import annotations

import base64
import hashlib
import hmac
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import mysql.connector
import paramiko
from dotenv import load_dotenv

try:
    from .credential_store import (
        CredentialEncryptionError,
        decrypt_credential_record,
    )
except ImportError:
    from credential_store import (
        CredentialEncryptionError,
        decrypt_credential_record,
    )


ENV_FILE = Path(__file__).resolve().parent / ".env"
load_dotenv(dotenv_path=ENV_FILE)


class TargetConfigurationError(RuntimeError):
    """Raised when a registered connection cannot be safely resolved."""


@dataclass(frozen=True)
class ResolvedSshTarget:
    target_id: str
    hostname: str
    port: int
    username: str
    password: str
    ssh_host_key_type: str
    ssh_host_key_base64: str
    ssh_host_key_fingerprint: str


@dataclass(frozen=True)
class ResolvedDatabaseTarget:
    database_target_id: str
    host: str
    port: int
    username: str
    password: str
    database_name: str
    read_only_required: bool


def _connect():
    required = {
        "DB_HOST": os.getenv("DB_HOST"),
        "DB_USER": os.getenv("DB_USER"),
        "DB_PASSWORD": os.getenv("DB_PASSWORD"),
        "DB_NAME": os.getenv("DB_NAME"),
    }
    missing = [name for name, value in required.items() if not value]
    if missing:
        raise TargetConfigurationError(
            "Missing registry database configuration: "
            + ", ".join(missing)
        )

    try:
        port = int(os.getenv("DB_PORT", "3306"))
    except ValueError as exc:
        raise TargetConfigurationError("DB_PORT must be an integer") from exc

    return mysql.connector.connect(
        host=required["DB_HOST"],
        port=port,
        user=required["DB_USER"],
        password=required["DB_PASSWORD"],
        database=required["DB_NAME"],
        connection_timeout=5,
        charset="utf8mb4",
        collation="utf8mb4_unicode_ci",
        use_unicode=True,
        use_pure=True,
    )


def _credential_fields() -> str:
    return """
        c.credential_id,
        c.credential_name,
        c.credential_type,
        c.purpose,
        c.encrypted_payload,
        c.encryption_nonce,
        c.key_version
    """


def _load_ssh_target_row(
    identifier: str,
    purpose: str,
) -> dict[str, Any]:
    credential_column = (
        "verifier_credential_id"
        if purpose == "VERIFIER"
        else "executor_credential_id"
    )
    connection = _connect()
    cursor = connection.cursor(dictionary=True)
    try:
        cursor.execute(
            f"""
            SELECT
                t.target_id,
                t.hostname,
                t.ssh_port,
                t.ssh_host_key_type,
                t.ssh_host_key_base64,
                t.ssh_host_key_fingerprint,
                {_credential_fields()}
            FROM registered_targets t
            INNER JOIN encrypted_credentials c
                ON c.credential_id = t.{credential_column}
               AND c.status = 'ACTIVE'
            WHERE t.enabled = 1
              AND (t.target_id = %s OR t.hostname = %s)
            LIMIT 2
            """,
            (identifier, identifier),
        )
        rows = cursor.fetchall()
    finally:
        cursor.close()
        connection.close()

    if not rows:
        raise TargetConfigurationError(
            f"No enabled {purpose.lower()} SSH target matches {identifier!r}"
        )
    if len(rows) != 1:
        raise TargetConfigurationError(
            f"SSH target identifier {identifier!r} is ambiguous"
        )
    return rows[0]


def _load_database_target_row(identifier: str) -> dict[str, Any]:
    connection = _connect()
    cursor = connection.cursor(dictionary=True)
    try:
        cursor.execute(
            f"""
            SELECT
                d.database_target_id,
                d.hostname,
                d.database_port,
                d.database_name,
                d.read_only_required,
                {_credential_fields()}
            FROM registered_database_targets d
            INNER JOIN encrypted_credentials c
                ON c.credential_id = d.credential_id
               AND c.status = 'ACTIVE'
            WHERE d.enabled = 1
              AND d.database_target_id = %s
            LIMIT 1
            """,
            (identifier,),
        )
        row = cursor.fetchone()
    finally:
        cursor.close()
        connection.close()

    if row is None:
        raise TargetConfigurationError(
            f"No enabled diagnostic database matches {identifier!r}"
        )
    return row


def _decrypt(
    row: dict[str, Any],
    *,
    expected_type: str,
    expected_purpose: str,
) -> dict[str, Any]:
    if row.get("credential_type") != expected_type:
        raise TargetConfigurationError(
            f"Credential {row.get('credential_name')} has type "
            f"{row.get('credential_type')!r}; expected {expected_type!r}"
        )
    if row.get("purpose") != expected_purpose:
        raise TargetConfigurationError(
            f"Credential {row.get('credential_name')} has purpose "
            f"{row.get('purpose')!r}; expected {expected_purpose!r}"
        )
    try:
        return decrypt_credential_record(row)
    except CredentialEncryptionError as exc:
        raise TargetConfigurationError(str(exc)) from exc


def _required_payload_value(
    payload: dict[str, Any],
    name: str,
    credential_name: Any,
) -> str:
    value = str(payload.get(name) or "").strip()
    if not value:
        raise TargetConfigurationError(
            f"Credential {credential_name!r} is missing {name}"
        )
    return value


def resolve_ssh_target(
    identifier: str,
    purpose: str,
) -> ResolvedSshTarget:
    """Resolve an SSH target and decrypt its purpose-specific credential."""

    normalized_purpose = str(purpose or "").strip().upper()
    expected_purposes = {
        "VERIFIER": "VERIFIER_READ_ONLY",
        "EXECUTOR": "EXECUTOR_REMEDIATION",
    }
    if normalized_purpose not in expected_purposes:
        raise TargetConfigurationError(
            "SSH target purpose must be VERIFIER or EXECUTOR"
        )

    normalized_identifier = str(identifier or "").strip()
    try:
        row = _load_ssh_target_row(
            normalized_identifier,
            normalized_purpose,
        )
        payload = _decrypt(
            row,
            expected_type="SSH_PASSWORD",
            expected_purpose=expected_purposes[normalized_purpose],
        )
    except TargetConfigurationError:
        raise
    except Exception as exc:
        raise TargetConfigurationError(
            f"Could not resolve SSH target {identifier!r}: {exc}"
        ) from exc

    try:
        port = int(row.get("ssh_port") or 22)
    except (TypeError, ValueError) as exc:
        raise TargetConfigurationError("SSH port must be an integer") from exc
    if not 1 <= port <= 65535:
        raise TargetConfigurationError("SSH port is outside 1-65535")

    return ResolvedSshTarget(
        target_id=str(row["target_id"]),
        hostname=str(row["hostname"]),
        port=port,
        username=_required_payload_value(
            payload,
            "username",
            row.get("credential_name"),
        ),
        password=_required_payload_value(
            payload,
            "password",
            row.get("credential_name"),
        ),
        ssh_host_key_type=str(row["ssh_host_key_type"]),
        ssh_host_key_base64=str(row["ssh_host_key_base64"]),
        ssh_host_key_fingerprint=str(row["ssh_host_key_fingerprint"]),
    )


def resolve_database_target(identifier: str) -> ResolvedDatabaseTarget:
    """Resolve a diagnostic database and decrypt its read-only credential."""

    normalized_identifier = str(identifier or "").strip()
    try:
        row = _load_database_target_row(normalized_identifier)
        payload = _decrypt(
            row,
            expected_type="DATABASE_PASSWORD",
            expected_purpose="DATABASE_READ_ONLY",
        )
    except TargetConfigurationError:
        raise
    except Exception as exc:
        raise TargetConfigurationError(
            f"Could not resolve database target {identifier!r}: {exc}"
        ) from exc

    try:
        port = int(row.get("database_port") or 3306)
    except (TypeError, ValueError) as exc:
        raise TargetConfigurationError(
            "Diagnostic database port must be an integer"
        ) from exc
    if not 1 <= port <= 65535:
        raise TargetConfigurationError(
            "Diagnostic database port is outside 1-65535"
        )
    if not bool(row.get("read_only_required")):
        raise TargetConfigurationError(
            f"Database target {normalized_identifier!r} is not registered "
            "for read-only diagnostics"
        )

    return ResolvedDatabaseTarget(
        database_target_id=str(row["database_target_id"]),
        host=str(row["hostname"]),
        port=port,
        username=_required_payload_value(
            payload,
            "username",
            row.get("credential_name"),
        ),
        password=_required_payload_value(
            payload,
            "password",
            row.get("credential_name"),
        ),
        database_name=str(row["database_name"]),
        read_only_required=bool(row.get("read_only_required")),
    )


def install_pinned_host_key(
    client: paramiko.SSHClient,
    target: ResolvedSshTarget,
) -> None:
    """Install and verify the database-pinned SSH host key in memory."""

    lookup_name = (
        target.hostname
        if target.port == 22
        else f"[{target.hostname}]:{target.port}"
    )
    try:
        key_data = base64.b64decode(
            target.ssh_host_key_base64.encode("ascii"),
            validate=True,
        )
        key = paramiko.PKey.from_type_string(
            target.ssh_host_key_type,
            key_data,
        )
    except Exception as exc:
        raise TargetConfigurationError(
            f"Target {target.target_id} has an invalid SSH host key"
        ) from exc

    fingerprint = "SHA256:" + base64.b64encode(
        hashlib.sha256(key.asbytes()).digest()
    ).decode("ascii").rstrip("=")
    if not hmac.compare_digest(
        fingerprint,
        target.ssh_host_key_fingerprint,
    ):
        raise TargetConfigurationError(
            f"Target {target.target_id} host-key fingerprint does not match"
        )

    client.get_host_keys().add(
        lookup_name,
        key.get_name(),
        key,
    )
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
