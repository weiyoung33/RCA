from __future__ import annotations

import base64
import json
import os
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class CredentialEncryptionError(RuntimeError):
    """Raised when encrypted credentials cannot be safely processed."""


def current_key_version() -> int:
    value = os.getenv("CREDENTIAL_MASTER_KEY_VERSION", "1")
    try:
        version = int(value)
    except ValueError as exc:
        raise CredentialEncryptionError(
            "CREDENTIAL_MASTER_KEY_VERSION must be an integer"
        ) from exc
    if version < 1:
        raise CredentialEncryptionError(
            "CREDENTIAL_MASTER_KEY_VERSION must be positive"
        )
    return version


def _master_key(version: int) -> bytes:
    versioned_name = f"CREDENTIAL_MASTER_KEY_V{version}"
    encoded = os.getenv(versioned_name)
    if not encoded and version == current_key_version():
        encoded = os.getenv("CREDENTIAL_MASTER_KEY")
    if not encoded:
        raise CredentialEncryptionError(
            f"Missing encryption key {versioned_name}"
        )

    try:
        key = base64.urlsafe_b64decode(encoded.strip().encode("ascii"))
    except Exception as exc:
        raise CredentialEncryptionError(
            f"Encryption key {versioned_name} is not valid URL-safe base64"
        ) from exc
    if len(key) != 32:
        raise CredentialEncryptionError(
            f"Encryption key {versioned_name} must decode to exactly 32 bytes"
        )
    return key


def _aad(
    credential_id: str,
    credential_type: str,
    purpose: str,
    key_version: int,
) -> bytes:
    return (
        "rca-credential:v1:"
        f"{credential_id}:{credential_type}:{purpose}:{key_version}"
    ).encode("utf-8")


def encrypt_credential_payload(
    credential_id: str,
    credential_type: str,
    purpose: str,
    payload: dict[str, Any],
) -> dict[str, Any]:
    """Encrypt a JSON credential payload with AES-256-GCM."""

    key_version = current_key_version()
    nonce = os.urandom(12)
    plaintext = json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    ciphertext = AESGCM(_master_key(key_version)).encrypt(
        nonce,
        plaintext,
        _aad(
            credential_id,
            credential_type,
            purpose,
            key_version,
        ),
    )
    return {
        "encrypted_payload": ciphertext,
        "encryption_nonce": nonce,
        "key_version": key_version,
    }


def decrypt_credential_record(record: dict[str, Any]) -> dict[str, Any]:
    """Authenticate and decrypt one credential record in memory."""

    try:
        credential_id = str(record["credential_id"])
        credential_type = str(record["credential_type"])
        purpose = str(record["purpose"])
        key_version = int(record["key_version"])
        nonce = bytes(record["encryption_nonce"])
        ciphertext = bytes(record["encrypted_payload"])
    except (KeyError, TypeError, ValueError) as exc:
        raise CredentialEncryptionError(
            "Encrypted credential record is incomplete"
        ) from exc

    if len(nonce) != 12:
        raise CredentialEncryptionError(
            f"Credential {credential_id} has an invalid AES-GCM nonce"
        )

    try:
        plaintext = AESGCM(_master_key(key_version)).decrypt(
            nonce,
            ciphertext,
            _aad(
                credential_id,
                credential_type,
                purpose,
                key_version,
            ),
        )
    except InvalidTag as exc:
        raise CredentialEncryptionError(
            f"Credential {credential_id} failed authentication"
        ) from exc

    try:
        payload = json.loads(plaintext.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CredentialEncryptionError(
            f"Credential {credential_id} contains an invalid payload"
        ) from exc
    if not isinstance(payload, dict):
        raise CredentialEncryptionError(
            f"Credential {credential_id} payload must be a JSON object"
        )
    return payload
