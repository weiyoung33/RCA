"""Validate and activate administrator-reviewed DAG onboarding bundles."""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import re
import socket
import uuid
from typing import Any, Optional

import mysql.connector
import paramiko
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .db import database_cursor
from .evidence_plan import is_source_sop, validate_source_activation
from .schemas import (
    OnboardingActionCatalogResponse,
    OnboardingActionOption,
    OnboardingActivationRequest,
    OnboardingActivationResponse,
    OnboardingDatabaseActivationCredentials,
    OnboardingExistingDatabaseTargetDraft,
    OnboardingExistingTargetDraft,
    OnboardingNewDatabaseTargetDraft,
    OnboardingNewTargetDraft,
    OnboardingSshActivationCredentials,
)


LOGGER = logging.getLogger("rca.onboarding_service")

IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{2,254}$")
CREDENTIAL_NAME_PATTERN = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9_.-]{2,149}$"
)
WRITE_PRIVILEGES = {
    "ALL",
    "ALL PRIVILEGES",
    "ALTER",
    "ALTER ROUTINE",
    "CREATE",
    "CREATE ROLE",
    "CREATE ROUTINE",
    "CREATE TABLESPACE",
    "CREATE TEMPORARY TABLES",
    "CREATE USER",
    "CREATE VIEW",
    "DELETE",
    "DROP",
    "DROP ROLE",
    "EVENT",
    "EXECUTE",
    "FILE",
    "INDEX",
    "INSERT",
    "LOCK TABLES",
    "REFERENCES",
    "RELOAD",
    "REPLACE",
    "SHUTDOWN",
    "SUPER",
    "TRIGGER",
    "TRUNCATE",
    "UPDATE",
}


class OnboardingServiceError(RuntimeError):
    """Base class for controlled onboarding failures."""


class OnboardingValidationError(OnboardingServiceError):
    """The reviewed bundle is incomplete or internally inconsistent."""


class OnboardingConflictError(OnboardingServiceError):
    """A DAG, target or credential identifier is already registered."""


class OnboardingTargetConnectionError(OnboardingServiceError):
    """A new target could not be authenticated and validated."""


class OnboardingConfigurationError(OnboardingServiceError):
    """A migration or credential-encryption setting is unavailable."""


class _CaptureHostKeyPolicy(paramiko.MissingHostKeyPolicy):
    """Capture the key presented by a new SSH server without persisting it."""

    def __init__(self) -> None:
        self.key: Optional[paramiko.PKey] = None

    def missing_host_key(
        self,
        client: paramiko.SSHClient,
        hostname: str,
        key: paramiko.PKey,
    ) -> None:
        _ = client, hostname
        self.key = key


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _normalized_text(value: Any) -> str:
    return " ".join(str(value or "").split()).casefold()


def _unique_nonempty(values: list[str]) -> list[str]:
    result: list[str] = []
    for value in values:
        text = str(value or "").strip()
        if text and text not in result:
            result.append(text)
    return result


def _key_version() -> int:
    try:
        version = int(os.getenv("CREDENTIAL_MASTER_KEY_VERSION", "1"))
    except ValueError as exc:
        raise OnboardingConfigurationError(
            "CREDENTIAL_MASTER_KEY_VERSION must be an integer"
        ) from exc
    if version < 1:
        raise OnboardingConfigurationError(
            "CREDENTIAL_MASTER_KEY_VERSION must be positive"
        )
    return version


def _master_key(version: int) -> bytes:
    variable_name = f"CREDENTIAL_MASTER_KEY_V{version}"
    encoded = os.getenv(variable_name)
    if not encoded and version == _key_version():
        encoded = os.getenv("CREDENTIAL_MASTER_KEY")
    if not encoded:
        raise OnboardingConfigurationError(
            f"Missing credential encryption key {variable_name}"
        )
    try:
        key = base64.urlsafe_b64decode(encoded.strip().encode("ascii"))
    except Exception as exc:
        raise OnboardingConfigurationError(
            f"Credential encryption key {variable_name} is invalid"
        ) from exc
    if len(key) != 32:
        raise OnboardingConfigurationError(
            f"Credential encryption key {variable_name} must decode to 32 bytes"
        )
    return key


def _credential_aad(
    credential_id: str,
    credential_type: str,
    purpose: str,
    key_version: int,
) -> bytes:
    return (
        "rca-credential:v1:"
        f"{credential_id}:{credential_type}:{purpose}:{key_version}"
    ).encode("utf-8")


def _encrypt_credential(
    credential_id: str,
    credential_type: str,
    purpose: str,
    username: str,
    password: str,
) -> dict[str, Any]:
    """Use the same AES-256-GCM format as agents/credential_store.py."""

    version = _key_version()
    nonce = os.urandom(12)
    plaintext = json.dumps(
        {"username": username, "password": password},
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    encrypted_payload = AESGCM(_master_key(version)).encrypt(
        nonce,
        plaintext,
        _credential_aad(
            credential_id,
            credential_type,
            purpose,
            version,
        ),
    )
    return {
        "encrypted_payload": encrypted_payload,
        "encryption_nonce": nonce,
        "key_version": version,
    }


def _host_key_metadata(key: paramiko.PKey) -> dict[str, str]:
    key_bytes = key.asbytes()
    fingerprint = "SHA256:" + base64.b64encode(
        hashlib.sha256(key_bytes).digest()
    ).decode("ascii").rstrip("=")
    return {
        "key_type": key.get_name(),
        "key_base64": base64.b64encode(key_bytes).decode("ascii"),
        "fingerprint": fingerprint,
    }


def _test_new_ssh_credential(
    hostname: str,
    port: int,
    username: str,
    password: str,
) -> dict[str, str]:
    policy = _CaptureHostKeyPolicy()
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(policy)
    try:
        client.connect(
            hostname=hostname,
            port=port,
            username=username,
            password=password,
            timeout=8,
            banner_timeout=8,
            auth_timeout=8,
            allow_agent=False,
            look_for_keys=False,
        )
        if policy.key is None:
            raise OnboardingTargetConnectionError(
                "The SSH server did not provide a host key"
            )
        return _host_key_metadata(policy.key)
    except OnboardingTargetConnectionError:
        raise
    except paramiko.AuthenticationException as exc:
        raise OnboardingTargetConnectionError(
            "The new SSH target rejected the supplied credentials"
        ) from exc
    except (
        paramiko.SSHException,
        socket.timeout,
        TimeoutError,
        OSError,
    ) as exc:
        raise OnboardingTargetConnectionError(
            f"The new SSH target could not be reached: {exc}"
        ) from exc
    finally:
        client.close()


def _validate_read_only_grants(grants: list[str]) -> None:
    if not grants:
        raise OnboardingTargetConnectionError(
            "The database account returned no grant information"
        )

    for grant in grants:
        upper = " ".join(grant.upper().split())
        if "WITH GRANT OPTION" in upper:
            raise OnboardingTargetConnectionError(
                "The database credential must not have GRANT OPTION"
            )
        if not upper.startswith("GRANT "):
            continue
        if " ON " not in upper:
            raise OnboardingTargetConnectionError(
                "A database role grant could not be proven read-only"
            )
        privilege_text = upper[6:].split(" ON ", 1)[0]
        privileges = {
            item.strip() for item in privilege_text.split(",") if item.strip()
        }
        blocked = sorted(privileges.intersection(WRITE_PRIVILEGES))
        if blocked:
            raise OnboardingTargetConnectionError(
                "The database credential is not read-only; blocked grants: "
                + ", ".join(blocked)
            )


def _test_database_credential(
    hostname: str,
    port: int,
    database_name: str,
    username: str,
    password: str,
) -> None:
    connection = None
    cursor = None
    try:
        connection = mysql.connector.connect(
            host=hostname,
            port=port,
            user=username,
            password=password,
            database=database_name,
            connection_timeout=8,
            charset="utf8mb4",
            use_unicode=True,
            autocommit=False,
        )
        cursor = connection.cursor()
        cursor.execute("SELECT 1 AS healthy")
        row = cursor.fetchone()
        if row is None or int(row[0]) != 1:
            raise OnboardingTargetConnectionError(
                "The database did not return the expected SELECT result"
            )
        cursor.execute("SHOW GRANTS")
        grants = [
            " ".join(str(value) for value in grant_row if value is not None)
            for grant_row in cursor.fetchall()
        ]
        _validate_read_only_grants(grants)
        connection.rollback()
    except OnboardingTargetConnectionError:
        if connection is not None:
            connection.rollback()
        raise
    except Exception as exc:
        if connection is not None:
            connection.rollback()
        raise OnboardingTargetConnectionError(
            f"The database target could not be validated: {exc}"
        ) from exc
    finally:
        if cursor is not None:
            cursor.close()
        if connection is not None:
            connection.close()


def _target_details(request: OnboardingActivationRequest) -> dict[str, Any]:
    registration = request.draft.target_registration
    if isinstance(registration, OnboardingExistingTargetDraft):
        return {
            "type": "SSH",
            "id": registration.target_id,
            "new": False,
            "sop_names": [registration.target_id],
        }
    if isinstance(registration, OnboardingExistingDatabaseTargetDraft):
        return {
            "type": "DATABASE",
            "id": registration.database_target_id,
            "new": False,
            "sop_names": [registration.database_target_id],
        }
    if isinstance(registration, OnboardingNewTargetDraft):
        return {
            "type": "SSH",
            "id": registration.target.target_id,
            "new": True,
            "sop_names": [
                registration.target.target_id,
                registration.target.hostname,
            ],
        }
    return {
        "type": "DATABASE",
        "id": registration.target.database_target_id,
        "new": True,
        "sop_names": [registration.target.database_target_id],
    }


def _validate_identifier(value: str, field_name: str) -> None:
    if not IDENTIFIER_PATTERN.fullmatch(value):
        raise OnboardingValidationError(
            f"{field_name} must use letters, numbers, dots, underscores or "
            "hyphens and must contain at least 3 characters"
        )


def _validate_credential_name(value: str, field_name: str) -> None:
    if not CREDENTIAL_NAME_PATTERN.fullmatch(value):
        raise OnboardingValidationError(
            f"{field_name} must use letters, numbers, dots, underscores or "
            "hyphens and must contain at least 3 characters"
        )


def _validate_request(request: OnboardingActivationRequest, source_audit: Optional[dict[str, Any]] = None) -> list[str]:
    draft = request.draft
    dag_id = draft.dag.dag_id.strip()
    _validate_identifier(dag_id, "DAG ID")

    exception_types = _unique_nonempty(draft.dag.exception_types)
    if not exception_types:
        raise OnboardingValidationError(
            "At least one exception type is required"
        )
    if any(len(value) > 255 for value in exception_types):
        raise OnboardingValidationError(
            "Each exception type must be 255 characters or fewer"
        )

    sop = draft.dag.investigation_sop.strip()
    if not sop:
        raise OnboardingValidationError("The final investigation SOP is required")

    # Revalidate the source plan against current target metadata before any
    # credentials are tested or persistent configuration is changed.
    if request.source_review is not None or is_source_sop(sop):
        context = {"ssh_targets": [], "database_targets": []}
        registration = draft.target_registration
        if isinstance(registration, (OnboardingExistingTargetDraft, OnboardingExistingDatabaseTargetDraft)):
            with database_cursor() as (_, cursor):
                if isinstance(registration, OnboardingExistingTargetDraft):
                    cursor.execute(
                        "SELECT target_id, hostname, ssh_port FROM registered_targets WHERE target_id = %s AND enabled = TRUE",
                        (registration.target_id,),
                    )
                    context["ssh_targets"] = cursor.fetchall()
                else:
                    cursor.execute(
                        "SELECT database_target_id, hostname, database_port, database_name FROM registered_database_targets WHERE database_target_id = %s AND enabled = TRUE AND read_only_required = TRUE",
                        (registration.database_target_id,),
                    )
                    context["database_targets"] = cursor.fetchall()
        try:
            source_plan = validate_source_activation(
                request.source_review.model_dump(mode="json") if request.source_review else None,
                draft.model_dump(mode="json"), context,
            )
            if source_audit is not None and source_plan is not None:
                review = source_plan["coverage_review"]
                if review["accepted"]:
                    source_audit.update({
                        "source_sha256": source_plan["source_sha256"],
                        "target": source_plan["target"],
                        "review_token": review["token"], "reason": review["reason"],
                        "accepted_warning_ids": review["warning_ids"],
                        "accepted_warnings": source_plan["unknowns"],
                        "final_classification": "INCONCLUSIVE",
                    })
        except ValueError as exc:
            raise OnboardingValidationError(str(exc)) from exc

    target = _target_details(request)
    _validate_identifier(str(target["id"]), "Target ID")
    normalized_sop = _normalized_text(sop)
    authorized_names = [
        _normalized_text(value)
        for value in target["sop_names"]
        if str(value or "").strip()
    ]
    if not any(name in normalized_sop for name in authorized_names):
        raise OnboardingValidationError(
            "The SOP must name the selected target ID or hostname"
        )

    registration = draft.target_registration
    if isinstance(registration, OnboardingNewTargetDraft):
        metadata = registration.target
        verifier = registration.credential_plan.verifier
        if not metadata.display_name or not metadata.hostname:
            raise OnboardingValidationError(
                "A new SSH target requires display_name and hostname"
            )
        if verifier.purpose != "VERIFIER_READ_ONLY" or not verifier.username:
            raise OnboardingValidationError(
                "A new SSH target requires a VERIFIER_READ_ONLY username"
            )
        _validate_credential_name(
            verifier.credential_name,
            "Verifier credential name",
        )

        executor = registration.credential_plan.executor
        if draft.operating_mode == "APPROVAL_REQUIRED_ACTION":
            if executor is None:
                raise OnboardingValidationError(
                    "Approval mode requires an executor credential plan"
                )
            if executor.purpose != "EXECUTOR_REMEDIATION" or not executor.username:
                raise OnboardingValidationError(
                    "Approval mode requires an EXECUTOR_REMEDIATION username"
                )
            _validate_credential_name(
                executor.credential_name,
                "Executor credential name",
            )
        elif executor is not None:
            raise OnboardingValidationError(
                "Investigate-only onboarding must not include an executor credential"
            )

    if isinstance(registration, OnboardingNewDatabaseTargetDraft):
        metadata = registration.target
        credential = registration.credential
        if not metadata.display_name or not metadata.hostname:
            raise OnboardingValidationError(
                "A new database target requires display_name and hostname"
            )
        if not metadata.database_name or not credential.username:
            raise OnboardingValidationError(
                "A new database target requires database_name and username"
            )
        _validate_credential_name(
            credential.credential_name,
            "Database credential name",
        )

    return exception_types


def _preflight_new_target(
    request: OnboardingActivationRequest,
) -> Optional[dict[str, str]]:
    """Test a new target before opening the control-database transaction."""

    registration = request.draft.target_registration
    if isinstance(registration, OnboardingNewTargetDraft):
        if not isinstance(
            request.credentials,
            OnboardingSshActivationCredentials,
        ):
            raise OnboardingValidationError(
                "New SSH targets require SSH_PASSWORDS credentials"
            )
        metadata = registration.target
        verifier = registration.credential_plan.verifier
        host_key = _test_new_ssh_credential(
            metadata.hostname,
            metadata.ssh_port,
            verifier.username,
            request.credentials.verifier_password.get_secret_value(),
        )

        executor = registration.credential_plan.executor
        executor_password = request.credentials.executor_password
        if executor is not None:
            if executor_password is None:
                raise OnboardingValidationError(
                    "The executor password is required"
                )
            second_key = _test_new_ssh_credential(
                metadata.hostname,
                metadata.ssh_port,
                executor.username,
                executor_password.get_secret_value(),
            )
            if second_key["fingerprint"] != host_key["fingerprint"]:
                raise OnboardingTargetConnectionError(
                    "The SSH server presented inconsistent host keys"
                )
        return host_key

    if isinstance(registration, OnboardingNewDatabaseTargetDraft):
        if not isinstance(
            request.credentials,
            OnboardingDatabaseActivationCredentials,
        ):
            raise OnboardingValidationError(
                "New database targets require DATABASE_PASSWORD credentials"
            )
        metadata = registration.target
        _test_database_credential(
            metadata.hostname,
            metadata.database_port,
            metadata.database_name,
            registration.credential.username,
            request.credentials.password.get_secret_value(),
        )
    return None


def _assert_dag_available(cursor: Any, dag_id: str) -> None:
    cursor.execute(
        "SELECT DAG_id FROM t_sops_master WHERE DAG_id = %s FOR UPDATE",
        (dag_id,),
    )
    if cursor.fetchone() is not None:
        raise OnboardingConflictError(
            "This DAG already has an SOP. Use the SOP editor to revise it."
        )
    cursor.execute(
        "SELECT dag_id FROM registered_dags WHERE dag_id = %s FOR UPDATE",
        (dag_id,),
    )
    if cursor.fetchone() is not None:
        raise OnboardingConflictError("This DAG is already registered")


def _assert_new_target_available(
    cursor: Any,
    request: OnboardingActivationRequest,
) -> None:
    registration = request.draft.target_registration
    if isinstance(registration, OnboardingNewTargetDraft):
        cursor.execute(
            """
            SELECT target_id
            FROM registered_targets
            WHERE target_id = %s OR hostname = %s
            LIMIT 1
            FOR UPDATE
            """,
            (registration.target.target_id, registration.target.hostname),
        )
        if cursor.fetchone() is not None:
            raise OnboardingConflictError(
                "The SSH target ID or hostname is already registered"
            )
    elif isinstance(registration, OnboardingNewDatabaseTargetDraft):
        cursor.execute(
            """
            SELECT database_target_id
            FROM registered_database_targets
            WHERE database_target_id = %s
            FOR UPDATE
            """,
            (registration.target.database_target_id,),
        )
        if cursor.fetchone() is not None:
            raise OnboardingConflictError(
                "The database target ID is already registered"
            )


def _validate_existing_target(
    cursor: Any,
    request: OnboardingActivationRequest,
) -> None:
    registration = request.draft.target_registration
    if isinstance(registration, OnboardingExistingTargetDraft):
        cursor.execute(
            """
            SELECT
                t.target_id,
                t.enabled,
                vc.credential_type AS verifier_type,
                vc.purpose AS verifier_purpose,
                vc.status AS verifier_status,
                ec.credential_type AS executor_type,
                ec.purpose AS executor_purpose,
                ec.status AS executor_status
            FROM registered_targets t
            LEFT JOIN encrypted_credentials vc
              ON vc.credential_id = t.verifier_credential_id
            LEFT JOIN encrypted_credentials ec
              ON ec.credential_id = t.executor_credential_id
            WHERE t.target_id = %s
            FOR UPDATE
            """,
            (registration.target_id,),
        )
        row = cursor.fetchone()
        if row is None or not bool(row["enabled"]):
            raise OnboardingValidationError(
                "The selected SSH target is not registered and enabled"
            )
        if (
            row["verifier_type"] != "SSH_PASSWORD"
            or row["verifier_purpose"] != "VERIFIER_READ_ONLY"
            or row["verifier_status"] != "ACTIVE"
        ):
            raise OnboardingValidationError(
                "The selected SSH target has no active verifier credential"
            )
        if request.draft.operating_mode == "APPROVAL_REQUIRED_ACTION" and (
            row["executor_type"] != "SSH_PASSWORD"
            or row["executor_purpose"] != "EXECUTOR_REMEDIATION"
            or row["executor_status"] != "ACTIVE"
        ):
            raise OnboardingValidationError(
                "The selected SSH target has no active executor credential"
            )

    elif isinstance(registration, OnboardingExistingDatabaseTargetDraft):
        cursor.execute(
            """
            SELECT
                d.database_target_id,
                d.read_only_required,
                d.enabled,
                c.credential_type,
                c.purpose,
                c.status
            FROM registered_database_targets d
            INNER JOIN encrypted_credentials c
              ON c.credential_id = d.credential_id
            WHERE d.database_target_id = %s
            FOR UPDATE
            """,
            (registration.database_target_id,),
        )
        row = cursor.fetchone()
        if row is None or not bool(row["enabled"]):
            raise OnboardingValidationError(
                "The selected database target is not registered and enabled"
            )
        if not bool(row["read_only_required"]):
            raise OnboardingValidationError(
                "The selected database target is not marked read-only"
            )
        if (
            row["credential_type"] != "DATABASE_PASSWORD"
            or row["purpose"] != "DATABASE_READ_ONLY"
            or row["status"] != "ACTIVE"
        ):
            raise OnboardingValidationError(
                "The selected database target has no active read-only credential"
            )


def _validate_selected_action(
    cursor: Any,
    request: OnboardingActivationRequest,
    target_id: str,
) -> None:
    action_id = request.draft.selected_action_id
    if action_id is None:
        return
    cursor.execute(
        """
        SELECT action_id, component_id, target_id,
               lifecycle_status, requires_approval
        FROM remediation_action_catalog
        WHERE action_id = %s
        FOR UPDATE
        """,
        (action_id,),
    )
    action = cursor.fetchone()
    if action is None:
        raise OnboardingValidationError(
            "The selected remediation action does not exist"
        )
    if action["lifecycle_status"] != "ACTIVE":
        raise OnboardingValidationError(
            "The selected remediation action is not ACTIVE"
        )
    if not bool(action["requires_approval"]):
        raise OnboardingValidationError(
            "The selected action does not require engineer approval"
        )
    if action["component_id"] != request.draft.dag.dag_id:
        raise OnboardingValidationError(
            "The selected action belongs to another DAG"
        )
    if action["target_id"] != target_id:
        raise OnboardingValidationError(
            "The selected action belongs to another target"
        )


def _insert_credential(
    cursor: Any,
    name: str,
    credential_type: str,
    purpose: str,
    username: str,
    password: str,
    actor: str,
) -> str:
    cursor.execute(
        """
        SELECT credential_id
        FROM encrypted_credentials
        WHERE credential_name = %s
        FOR UPDATE
        """,
        (name,),
    )
    if cursor.fetchone() is not None:
        raise OnboardingConflictError(
            f"Credential name {name!r} is already registered"
        )

    credential_id = str(uuid.uuid4())
    encrypted = _encrypt_credential(
        credential_id,
        credential_type,
        purpose,
        username,
        password,
    )
    cursor.execute(
        """
        INSERT INTO encrypted_credentials (
            credential_id, credential_name, credential_type, purpose,
            encrypted_payload, encryption_nonce, key_version, status,
            created_by, updated_by, updated_at
        ) VALUES (
            %s, %s, %s, %s, %s, %s, %s,
            'ACTIVE', %s, %s, CURRENT_TIMESTAMP
        )
        """,
        (
            credential_id,
            name,
            credential_type,
            purpose,
            encrypted["encrypted_payload"],
            encrypted["encryption_nonce"],
            encrypted["key_version"],
            actor,
            actor,
        ),
    )
    return credential_id


def _insert_new_target(
    cursor: Any,
    request: OnboardingActivationRequest,
    host_key: Optional[dict[str, str]],
    actor: str,
) -> None:
    registration = request.draft.target_registration
    if isinstance(registration, OnboardingNewTargetDraft):
        if not isinstance(
            request.credentials,
            OnboardingSshActivationCredentials,
        ) or host_key is None:
            raise OnboardingValidationError(
                "Validated SSH credentials and host key are required"
            )

        verifier = registration.credential_plan.verifier
        verifier_id = _insert_credential(
            cursor,
            verifier.credential_name,
            "SSH_PASSWORD",
            "VERIFIER_READ_ONLY",
            verifier.username,
            request.credentials.verifier_password.get_secret_value(),
            actor,
        )
        executor_id: Optional[str] = None
        executor = registration.credential_plan.executor
        executor_password = request.credentials.executor_password
        if executor is not None and executor_password is not None:
            executor_id = _insert_credential(
                cursor,
                executor.credential_name,
                "SSH_PASSWORD",
                "EXECUTOR_REMEDIATION",
                executor.username,
                executor_password.get_secret_value(),
                actor,
            )

        metadata = registration.target
        cursor.execute(
            """
            INSERT INTO registered_targets (
                target_id, display_name, hostname, ssh_port,
                ssh_host_key_type, ssh_host_key_base64,
                ssh_host_key_fingerprint, verifier_credential_id,
                executor_credential_id, enabled,
                created_by, updated_by, updated_at
            ) VALUES (
                %s, %s, %s, %s, %s, %s, %s, %s, %s,
                TRUE, %s, %s, CURRENT_TIMESTAMP
            )
            """,
            (
                metadata.target_id,
                metadata.display_name,
                metadata.hostname,
                metadata.ssh_port,
                host_key["key_type"],
                host_key["key_base64"],
                host_key["fingerprint"],
                verifier_id,
                executor_id,
                actor,
                actor,
            ),
        )

    elif isinstance(registration, OnboardingNewDatabaseTargetDraft):
        if not isinstance(
            request.credentials,
            OnboardingDatabaseActivationCredentials,
        ):
            raise OnboardingValidationError(
                "Validated database credentials are required"
            )
        credential = registration.credential
        credential_id = _insert_credential(
            cursor,
            credential.credential_name,
            "DATABASE_PASSWORD",
            "DATABASE_READ_ONLY",
            credential.username,
            request.credentials.password.get_secret_value(),
            actor,
        )
        metadata = registration.target
        cursor.execute(
            """
            INSERT INTO registered_database_targets (
                database_target_id, display_name, hostname,
                database_port, database_name, credential_id,
                read_only_required, enabled,
                created_by, updated_by, updated_at
            ) VALUES (
                %s, %s, %s, %s, %s, %s,
                TRUE, TRUE, %s, %s, CURRENT_TIMESTAMP
            )
            """,
            (
                metadata.database_target_id,
                metadata.display_name,
                metadata.hostname,
                metadata.database_port,
                metadata.database_name,
                credential_id,
                actor,
                actor,
            ),
        )


def _insert_dag_records(
    cursor: Any,
    request: OnboardingActivationRequest,
    exception_types: list[str],
    actor: str,
) -> None:
    draft = request.draft
    cursor.execute(
        """
        INSERT INTO t_sops_master (DAG_id, investigation_sop)
        VALUES (%s, %s)
        """,
        (draft.dag.dag_id, draft.dag.investigation_sop),
    )
    cursor.execute(
        """
        INSERT INTO registered_dags (
            dag_id, operating_mode, exception_types,
            remediation_action_id, lifecycle_status,
            created_by, updated_by
        ) VALUES (%s, %s, %s, %s, 'ACTIVE', %s, %s)
        """,
        (
            draft.dag.dag_id,
            draft.operating_mode,
            json.dumps(exception_types, ensure_ascii=False),
            draft.selected_action_id,
            actor,
            actor,
        ),
    )


def _insert_audit_event(
    cursor: Any,
    request: OnboardingActivationRequest,
    target: dict[str, Any],
    sop_hash: str,
    actor: str,
    source_audit: Optional[dict[str, Any]] = None,
) -> None:
    details = {
        "schema_version": request.draft.schema_version,
        "operating_mode": request.draft.operating_mode,
        "exception_types": _unique_nonempty(
            request.draft.dag.exception_types
        ),
        "target_created": bool(target["new"]),
        "credentials_created": bool(target["new"]),
        "sop_content_hash": sop_hash,
    }
    if source_audit:
        details["limited_coverage_acknowledgement"] = {**source_audit, "accepted_by": actor}
    cursor.execute(
        """
        INSERT INTO onboarding_events (
            dag_id, event_type, target_type, target_id,
            remediation_action_id, performed_by, event_details
        ) VALUES (%s, 'ACTIVATED', %s, %s, %s, %s, %s)
        """,
        (
            request.draft.dag.dag_id,
            target["type"],
            target["id"],
            request.draft.selected_action_id,
            actor,
            json.dumps(details, ensure_ascii=False),
        ),
    )


def list_active_onboarding_actions(
    component_id: Optional[str] = None,
    target_id: Optional[str] = None,
) -> OnboardingActionCatalogResponse:
    """Return only ACTIVE, approval-required action definitions."""

    conditions = [
        "lifecycle_status = 'ACTIVE'",
        "requires_approval = TRUE",
    ]
    parameters: list[Any] = []
    if component_id:
        conditions.append("component_id = %s")
        parameters.append(component_id)
    if target_id:
        conditions.append("target_id = %s")
        parameters.append(target_id)

    with database_cursor() as (_, cursor):
        cursor.execute(
            f"""
            SELECT
                action_id, component_id, target_id, display_name,
                description, risk_level, implementation_version,
                requires_approval
            FROM remediation_action_catalog
            WHERE {' AND '.join(conditions)}
            ORDER BY display_name, action_id
            """,
            tuple(parameters),
        )
        rows = cursor.fetchall()

    return OnboardingActionCatalogResponse(
        items=[
            OnboardingActionOption(
                action_id=str(row["action_id"]),
                component_id=str(row["component_id"]),
                target_id=str(row["target_id"]),
                display_name=str(row["display_name"]),
                description=str(row["description"]),
                risk_level=str(row["risk_level"]),
                implementation_version=str(row["implementation_version"]),
                requires_approval=bool(row["requires_approval"]),
            )
            for row in rows
        ]
    )


def activate_onboarding(
    request: OnboardingActivationRequest,
    activated_by: str,
) -> OnboardingActivationResponse:
    """Validate and atomically activate one new DAG and its dependencies."""

    actor = str(activated_by or "").strip()
    if not actor:
        raise OnboardingValidationError(
            "An authenticated administrator identity is required"
        )

    source_audit: dict[str, Any] = {}
    exception_types = _validate_request(request, source_audit)
    target = _target_details(request)
    host_key = _preflight_new_target(request)
    sop_hash = _sha256_text(request.draft.dag.investigation_sop)

    try:
        with database_cursor(commit=True) as (_, cursor):
            _assert_dag_available(cursor, request.draft.dag.dag_id)
            _assert_new_target_available(cursor, request)
            _validate_existing_target(cursor, request)
            _validate_selected_action(cursor, request, str(target["id"]))
            _insert_new_target(cursor, request, host_key, actor)
            _insert_dag_records(cursor, request, exception_types, actor)
            _insert_audit_event(cursor, request, target, sop_hash, actor, source_audit)
    except OnboardingServiceError:
        raise
    except mysql.connector.IntegrityError as exc:
        if getattr(exc, "errno", None) == 1062:
            raise OnboardingConflictError(
                "The DAG, target or credential was registered concurrently"
            ) from exc
        raise OnboardingServiceError(
            "The onboarding transaction violated a database constraint"
        ) from exc
    except mysql.connector.ProgrammingError as exc:
        if getattr(exc, "errno", None) == 1146:
            raise OnboardingConfigurationError(
                "The onboarding database migration has not been applied"
            ) from exc
        raise OnboardingServiceError(
            "The onboarding transaction could not be completed"
        ) from exc
    except Exception as exc:
        raise OnboardingServiceError(
            "The onboarding transaction could not be completed"
        ) from exc

    LOGGER.info(
        "Activated DAG %s with target %s by %s",
        request.draft.dag.dag_id,
        target["id"],
        actor,
    )
    return OnboardingActivationResponse(
        dag_id=request.draft.dag.dag_id,
        operating_mode=request.draft.operating_mode,
        target_type=target["type"],
        target_id=str(target["id"]),
        target_created=bool(target["new"]),
        credentials_created=bool(target["new"]),
        selected_action_id=request.draft.selected_action_id,
        sop_content_hash=sop_hash,
        activated_by=actor,
        message="DAG, SOP and target configuration activated successfully",
    )
