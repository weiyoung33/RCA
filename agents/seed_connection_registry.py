from __future__ import annotations

import argparse
import base64
import hashlib
import os
import uuid
from pathlib import Path
from typing import Any, Optional

import mysql.connector
import paramiko
from dotenv import load_dotenv

try:
    from .credential_store import encrypt_credential_payload
except ImportError:
    from credential_store import encrypt_credential_payload


ENV_FILE = Path(__file__).resolve().parent / ".env"
load_dotenv(dotenv_path=ENV_FILE)


# Temporary import definitions for the project's current connections. Future
# Admin GUI endpoints will replace this one-time seeding file.
SSH_TARGETS = (
    {
        "target_id": "SZS_SZSSXV00110_SSH",
        "display_name": "SZS SSH Host — szssxv00110",
        "hostname": "szssxv00110.szs.st.com",
        "port": 22,
        "credentials": {
            "VERIFIER": {
                "credential_name": "SZS_SZSSXV00110_VERIFIER",
                "purpose": "VERIFIER_READ_ONLY",
                "username_env": "SZS_SZSSXV00110_USER",
                "password_env": "SZS_SZSSXV00110_PASS",
                "known_hosts_env": "SZS_SZSSXV00110_KNOWN_HOSTS",
            },
        },
    },
    {
        "target_id": "KIRSX00300",
        "display_name": "AXI Classification ETL server",
        "hostname": "kirsx00300.kir.st.com",
        "port": 22,
        "credentials": {
            "VERIFIER": {
                "credential_name": "KIRSX00300_VERIFIER",
                "purpose": "VERIFIER_READ_ONLY",
                "username_env": "KIRSX00300_USER",
                "password_env": "KIRSX00300_PASS",
                "known_hosts_env": "KIRSX00300_KNOWN_HOSTS",
            },
        },
    },
    {
        "target_id": "KIRSX00317",
        "display_name": "Flipchip Linux application server",
        "hostname": "kirsx00317.kir.st.com",
        "port": 22,
        "credentials": {
            "VERIFIER": {
                "credential_name": "KIRSX00317_VERIFIER",
                "purpose": "VERIFIER_READ_ONLY",
                "username_env": "KIRSX00317_USER",
                "password_env": "KIRSX00317_PASS",
                "known_hosts_env": "KIRSX00317_KNOWN_HOSTS",
            },
        },
    },
    {
        "target_id": "MUASXV4106",
        "display_name": "Ansible web application server",
        "hostname": "muasxv4106.mua.st.com",
        "hostname_env": "EXECUTOR_TARGET_MUASXV4106_HOST",
        "port": 22,
        "credentials": {
            "VERIFIER": {
                "credential_name": "MUASXV4106_VERIFIER",
                "purpose": "VERIFIER_READ_ONLY",
                "username_env": "MUASXV4106_USER",
                "password_env": "MUASXV4106_PASS",
                "known_hosts_env": "MUASXV4106_KNOWN_HOSTS",
            },
            "EXECUTOR": {
                "credential_name": "MUASXV4106_EXECUTOR",
                "purpose": "EXECUTOR_REMEDIATION",
                "username_env": "EXECUTOR_TARGET_MUASXV4106_SSH_USER",
                "password_env": "EXECUTOR_TARGET_MUASXV4106_SSH_PASSWORD",
                "known_hosts_env": (
                    "EXECUTOR_TARGET_MUASXV4106_KNOWN_HOSTS"
                ),
            },
        },
    },
    {
        "target_id": "JUMPING_STATION_10_56_157_156",
        "display_name": "Flipchip jumping station",
        "hostname": "10.56.157.156",
        "port": 22,
        "credentials": {
            "VERIFIER": {
                "credential_name": "JUMPING_STATION_VERIFIER",
                "purpose": "VERIFIER_READ_ONLY",
                "username_env": "10_56_157_156_USER",
                "password_env": "10_56_157_156_PASS",
                "known_hosts_env": "10_56_157_156_KNOWN_HOSTS",
            },
        },
    },
)


DATABASE_TARGETS = (
    {
        "database_target_id": "CAPILLARY_PRD_DB",
        "display_name": "Capillary production database",
        "host_env": "CAPILLARY_DB_HOST",
        "port_env": "CAPILLARY_DB_PORT",
        "username_env": "CAPILLARY_DB_USER",
        "password_env": "CAPILLARY_DB_PASS",
        "database_name_env": "CAPILLARY_DB_NAME",
        "credential_name": "CAPILLARY_DB_VERIFIER",
    },
    {
        "database_target_id": "AXIIMGCLASS_PRD_DB",
        "display_name": "AXI Classification production database",
        "host_env": "AXIIMGCLASS_DB_HOST",
        "port_env": "AXIIMGCLASS_DB_PORT",
        "username_env": "AXIIMGCLASS_DB_USER",
        "password_env": "AXIIMGCLASS_DB_PASS",
        "database_name_env": "AXIIMGCLASS_DB_NAME",
        "credential_name": "AXIIMGCLASS_DB_VERIFIER",
    },
    {
        "database_target_id": "FLIPCHIP_DB",
        "display_name": "Flipchip production database",
        "host_env": "FLIPCHIP_DB_HOST",
        "port_env": "FLIPCHIP_DB_PORT",
        "username_env": "FLIPCHIP_DB_USER",
        "password_env": "FLIPCHIP_DB_PASS",
        "database_name_env": "FLIPCHIP_DB_NAME",
        "credential_name": "FLIPCHIP_DB_VERIFIER",
    },
    {
        "database_target_id": "TEST_DB",
        "display_name": "ML monitor test database",
        "host_env": "TEST_DB_HOST",
        "port_env": "TEST_DB_PORT",
        "username_env": "TEST_DB_USER",
        "password_env": "TEST_DB_PASS",
        "database_name_env": "TEST_DB_NAME",
        "credential_name": "TEST_DB_VERIFIER",
    },
    {
        "database_target_id": "AOIBURR_PRD_DB",
        "display_name": "AOI Burr production database",
        "host_env": "AOIBURR_PRD_DB_HOST",
        "port_env": "AOIBURR_PRD_DB_PORT",
        "username_env": "AOIBURR_PRD_DB_USER",
        "password_env": "AOIBURR_PRD_DB_PASS",
        "database_name_env": "AOIBURR_PRD_DB_NAME",
        "credential_name": "AOIBURR_PRD_DB_VERIFIER",
    },
)


def _connect():
    names = ("DB_HOST", "DB_USER", "DB_PASSWORD", "DB_NAME")
    missing = [name for name in names if not os.getenv(name)]
    if missing:
        raise RuntimeError(
            "Missing RCA database configuration: " + ", ".join(missing)
        )
    return mysql.connector.connect(
        host=os.environ["DB_HOST"],
        port=int(os.getenv("DB_PORT", "3306")),
        user=os.environ["DB_USER"],
        password=os.environ["DB_PASSWORD"],
        database=os.environ["DB_NAME"],
        connection_timeout=5,
        charset="utf8mb4",
        collation="utf8mb4_unicode_ci",
        use_unicode=True,
    )


def _optional_profile(environment_names: list[str]) -> Optional[dict[str, str]]:
    values = {name: str(os.getenv(name) or "").strip() for name in environment_names}
    configured = [name for name, value in values.items() if value]
    if not configured:
        return None
    missing = [name for name, value in values.items() if not value]
    if missing:
        raise RuntimeError(
            "Partially configured credential profile. Missing: "
            + ", ".join(missing)
        )
    return values


def _host_key(
    hostname: str,
    port: int,
    known_hosts_path: str,
) -> dict[str, str]:
    path = Path(known_hosts_path).expanduser()
    if not path.is_file():
        raise RuntimeError(f"known_hosts file does not exist: {path}")

    host_keys = paramiko.HostKeys()
    host_keys.load(str(path))
    lookup_name = hostname if port == 22 else f"[{hostname}]:{port}"
    matching = host_keys.lookup(lookup_name)
    if not matching:
        raise RuntimeError(
            f"Server {lookup_name!r} is not present in known_hosts"
        )

    preferred_types = (
        "ssh-ed25519",
        "ecdsa-sha2-nistp256",
        "ecdsa-sha2-nistp384",
        "ecdsa-sha2-nistp521",
        "rsa-sha2-512",
        "rsa-sha2-256",
        "ssh-rsa",
    )
    key_type = next(
        (name for name in preferred_types if name in matching),
        next(iter(matching)),
    )
    key = matching[key_type]
    fingerprint = "SHA256:" + base64.b64encode(
        hashlib.sha256(key.asbytes()).digest()
    ).decode("ascii").rstrip("=")
    return {
        "key_type": key.get_name(),
        "key_base64": base64.b64encode(key.asbytes()).decode("ascii"),
        "fingerprint": fingerprint,
    }


def _upsert_credential(
    cursor: Any,
    credential_name: str,
    credential_type: str,
    purpose: str,
    payload: dict[str, str],
) -> str:
    cursor.execute(
        """
        SELECT credential_id
        FROM encrypted_credentials
        WHERE credential_name = %s
        LIMIT 1
        """,
        (credential_name,),
    )
    existing = cursor.fetchone()
    credential_id = (
        str(existing["credential_id"])
        if existing
        else str(uuid.uuid4())
    )
    encrypted = encrypt_credential_payload(
        credential_id,
        credential_type,
        purpose,
        payload,
    )
    cursor.execute(
        """
        INSERT INTO encrypted_credentials (
            credential_id,
            credential_name,
            credential_type,
            purpose,
            encrypted_payload,
            encryption_nonce,
            key_version,
            status,
            created_by,
            updated_by,
            updated_at
        ) VALUES (
            %s, %s, %s, %s, %s, %s, %s,
            'ACTIVE', 'seed-script', 'seed-script', CURRENT_TIMESTAMP
        )
        ON DUPLICATE KEY UPDATE
            credential_type = VALUES(credential_type),
            purpose = VALUES(purpose),
            encrypted_payload = VALUES(encrypted_payload),
            encryption_nonce = VALUES(encryption_nonce),
            key_version = VALUES(key_version),
            status = 'ACTIVE',
            updated_by = 'seed-script',
            updated_at = CURRENT_TIMESTAMP
        """,
        (
            credential_id,
            credential_name,
            credential_type,
            purpose,
            encrypted["encrypted_payload"],
            encrypted["encryption_nonce"],
            encrypted["key_version"],
        ),
    )
    return credential_id


def _seed_ssh_targets(
    cursor: Any,
    target_id: Optional[str] = None,
) -> list[str]:
    seeded: list[str] = []
    for definition in SSH_TARGETS:
        if target_id is not None and definition["target_id"] != target_id:
            continue

        hostname = str(
            os.getenv(str(definition.get("hostname_env") or ""))
            or definition["hostname"]
        ).strip()
        port = int(definition["port"])
        credential_ids: dict[str, Optional[str]] = {
            "VERIFIER": None,
            "EXECUTOR": None,
        }
        host_key: Optional[dict[str, str]] = None

        for role, profile in definition["credentials"].items():
            environment_names = [
                profile["username_env"],
                profile["password_env"],
                profile["known_hosts_env"],
            ]
            values = _optional_profile(environment_names)
            if values is None:
                continue
            if host_key is None:
                host_key = _host_key(
                    hostname,
                    port,
                    values[profile["known_hosts_env"]],
                )
            credential_ids[role] = _upsert_credential(
                cursor,
                profile["credential_name"],
                "SSH_PASSWORD",
                profile["purpose"],
                {
                    "username": values[profile["username_env"]],
                    "password": values[profile["password_env"]],
                },
            )

        if host_key is None:
            continue

        cursor.execute(
            """
            INSERT INTO registered_targets (
                target_id,
                display_name,
                hostname,
                ssh_port,
                ssh_host_key_type,
                ssh_host_key_base64,
                ssh_host_key_fingerprint,
                verifier_credential_id,
                executor_credential_id,
                enabled,
                created_by,
                updated_by,
                updated_at
            ) VALUES (
                %s, %s, %s, %s, %s, %s, %s, %s, %s,
                TRUE, 'seed-script', 'seed-script', CURRENT_TIMESTAMP
            )
            ON DUPLICATE KEY UPDATE
                display_name = VALUES(display_name),
                hostname = VALUES(hostname),
                ssh_port = VALUES(ssh_port),
                ssh_host_key_type = VALUES(ssh_host_key_type),
                ssh_host_key_base64 = VALUES(ssh_host_key_base64),
                ssh_host_key_fingerprint = VALUES(ssh_host_key_fingerprint),
                verifier_credential_id = COALESCE(
                    VALUES(verifier_credential_id),
                    verifier_credential_id
                ),
                executor_credential_id = COALESCE(
                    VALUES(executor_credential_id),
                    executor_credential_id
                ),
                enabled = TRUE,
                updated_by = 'seed-script',
                updated_at = CURRENT_TIMESTAMP
            """,
            (
                definition["target_id"],
                definition["display_name"],
                hostname,
                port,
                host_key["key_type"],
                host_key["key_base64"],
                host_key["fingerprint"],
                credential_ids["VERIFIER"],
                credential_ids["EXECUTOR"],
            ),
        )
        seeded.append(str(definition["target_id"]))
    return seeded


def _seed_database_targets(
    cursor: Any,
    database_target_id: Optional[str] = None,
) -> list[str]:
    seeded: list[str] = []
    for definition in DATABASE_TARGETS:
        if (
            database_target_id is not None
            and definition["database_target_id"] != database_target_id
        ):
            continue
        environment_names = [
            definition["host_env"],
            definition["port_env"],
            definition["username_env"],
            definition["password_env"],
            definition["database_name_env"],
        ]
        values = _optional_profile(environment_names)
        if values is None:
            continue
        port = int(values[definition["port_env"]])
        credential_id = _upsert_credential(
            cursor,
            definition["credential_name"],
            "DATABASE_PASSWORD",
            "DATABASE_READ_ONLY",
            {
                "username": values[definition["username_env"]],
                "password": values[definition["password_env"]],
            },
        )
        cursor.execute(
            """
            INSERT INTO registered_database_targets (
                database_target_id,
                display_name,
                hostname,
                database_port,
                database_name,
                credential_id,
                read_only_required,
                enabled,
                created_by,
                updated_by,
                updated_at
            ) VALUES (
                %s, %s, %s, %s, %s, %s,
                TRUE, TRUE, 'seed-script', 'seed-script', CURRENT_TIMESTAMP
            )
            ON DUPLICATE KEY UPDATE
                display_name = VALUES(display_name),
                hostname = VALUES(hostname),
                database_port = VALUES(database_port),
                database_name = VALUES(database_name),
                credential_id = VALUES(credential_id),
                read_only_required = TRUE,
                enabled = TRUE,
                updated_by = 'seed-script',
                updated_at = CURRENT_TIMESTAMP
            """,
            (
                definition["database_target_id"],
                definition["display_name"],
                values[definition["host_env"]],
                port,
                values[definition["database_name_env"]],
                credential_id,
            ),
        )
        seeded.append(str(definition["database_target_id"]))
    return seeded


def seed(
    target_id: Optional[str] = None,
    database_target_id: Optional[str] = None,
) -> None:
    if target_id is not None and database_target_id is not None:
        raise ValueError("Choose either an SSH target or a database target")
    connection = _connect()
    cursor = connection.cursor(dictionary=True)
    try:
        ssh_targets = (
            [] if database_target_id is not None
            else _seed_ssh_targets(cursor, target_id)
        )
        if target_id is not None and not ssh_targets:
            raise RuntimeError(
                f"No complete credential profile configured for {target_id}"
            )
        database_targets = (
            [] if target_id is not None
            else _seed_database_targets(cursor, database_target_id)
        )
        if database_target_id is not None and not database_targets:
            raise RuntimeError(
                "No complete credential profile configured for "
                + database_target_id
            )
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        cursor.close()
        connection.close()

    print("Seeded SSH targets:", ssh_targets or "none")
    print("Seeded database targets:", database_targets or "none")
    print("No plaintext credentials were written to the database.")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Encrypt current .env credentials into the RCA registry"
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="perform the database writes",
    )
    scope = parser.add_mutually_exclusive_group()
    scope.add_argument(
        "--target-id",
        choices=tuple(item["target_id"] for item in SSH_TARGETS),
        help="seed only this SSH target; skip database targets",
    )
    scope.add_argument(
        "--database-target-id",
        choices=tuple(item["database_target_id"] for item in DATABASE_TARGETS),
        help="seed only this database target; skip SSH targets",
    )
    args = parser.parse_args()

    if not args.apply:
        print("Dry run only; no database changes were made.")
        print("Run again with --apply after reviewing the migration and .env.")
        return
    seed(
        target_id=args.target_id,
        database_target_id=args.database_target_id,
    )


if __name__ == "__main__":
    main()
