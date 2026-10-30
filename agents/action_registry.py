from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Union


SUPPORTED_EXECUTOR_TYPES = frozenset({"SSH_COMMAND"})
MAX_COMMAND_CHARS = 16_000


class ActionDefinitionError(ValueError):
    """Raised when a database action definition is invalid or unsafe to load."""


@dataclass(frozen=True)
class CommandCheck:
    """A remote diagnostic command interpreted using explicit result rules."""

    name: str
    command: str
    expected_exit_codes: tuple[int, ...] = (0,)
    timeout_seconds: int = 15
    unhealthy_exit_codes: tuple[int, ...] = (1,)
    require_stdout: bool = False
    healthy_stdout_regex: str | None = None
    unhealthy_stdout_regex: str | None = None


@dataclass(frozen=True)
class HttpCheck:
    """A URL checked with curl from the registered target host."""

    name: str
    url: str
    expected_status_codes: tuple[int, ...] = (200,)
    timeout_seconds: int = 10


VerificationCheck = Union[CommandCheck, HttpCheck]


@dataclass(frozen=True)
class ActionDefinition:
    """A validated, versioned action loaded from the database catalog."""

    action_id: str
    component_id: str
    target_id: str
    implementation_version: str
    executor_type: str
    command: str
    precheck_checks: tuple[VerificationCheck, ...]
    postcheck_checks: tuple[VerificationCheck, ...]
    command_timeout_seconds: int = 60
    verification_attempts: int = 6
    verification_delay_seconds: int = 5


def _mapping(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ActionDefinitionError(f"{field} must be a JSON object")
    return value


def _only_keys(value: dict[str, Any], allowed: set[str], field: str) -> None:
    unexpected = sorted(set(value) - allowed)
    if unexpected:
        raise ActionDefinitionError(
            f"{field} contains unsupported field(s): {', '.join(unexpected)}"
        )


def _required_text(
    value: Any,
    field: str,
    *,
    maximum: int,
) -> str:
    text = str(value or "").strip()
    if not text:
        raise ActionDefinitionError(f"{field} is required")
    if "\x00" in text:
        raise ActionDefinitionError(f"{field} contains a null byte")
    if len(text) > maximum:
        raise ActionDefinitionError(
            f"{field} exceeds the maximum length of {maximum} characters"
        )
    return text


def _integer(
    value: Any,
    field: str,
    *,
    minimum: int,
    maximum: int,
) -> int:
    if isinstance(value, bool):
        raise ActionDefinitionError(f"{field} must be an integer")
    try:
        number = int(value)
    except (TypeError, ValueError) as exc:
        raise ActionDefinitionError(f"{field} must be an integer") from exc
    if not minimum <= number <= maximum:
        raise ActionDefinitionError(
            f"{field} must be between {minimum} and {maximum}"
        )
    return number


def _integer_tuple(
    value: Any,
    field: str,
    *,
    default: tuple[int, ...],
    minimum: int,
    maximum: int,
) -> tuple[int, ...]:
    if value is None:
        return default
    if not isinstance(value, list) or not value:
        raise ActionDefinitionError(f"{field} must be a non-empty JSON array")
    numbers = tuple(
        _integer(
            item,
            f"{field}[{index}]",
            minimum=minimum,
            maximum=maximum,
        )
        for index, item in enumerate(value)
    )
    if len(set(numbers)) != len(numbers):
        raise ActionDefinitionError(f"{field} contains duplicate values")
    return numbers


def _optional_regex(value: Any, field: str) -> str | None:
    if value is None:
        return None
    pattern = _required_text(value, field, maximum=2_000)
    try:
        re.compile(pattern)
    except re.error as exc:
        raise ActionDefinitionError(f"{field} is not a valid regular expression") from exc
    return pattern


def _parse_check(value: Any, field: str) -> VerificationCheck:
    check = _mapping(value, field)
    kind = str(check.get("kind") or "").strip().lower()

    if kind == "command":
        _only_keys(
            check,
            {
                "kind",
                "name",
                "command",
                "expected_exit_codes",
                "unhealthy_exit_codes",
                "timeout_seconds",
                "require_stdout",
                "healthy_stdout_regex",
                "unhealthy_stdout_regex",
            },
            field,
        )
        require_stdout = check.get("require_stdout", False)
        if not isinstance(require_stdout, bool):
            raise ActionDefinitionError(f"{field}.require_stdout must be boolean")
        return CommandCheck(
            name=_required_text(check.get("name"), f"{field}.name", maximum=128),
            command=_required_text(
                check.get("command"),
                f"{field}.command",
                maximum=MAX_COMMAND_CHARS,
            ),
            expected_exit_codes=_integer_tuple(
                check.get("expected_exit_codes"),
                f"{field}.expected_exit_codes",
                default=(0,),
                minimum=0,
                maximum=255,
            ),
            unhealthy_exit_codes=_integer_tuple(
                check.get("unhealthy_exit_codes"),
                f"{field}.unhealthy_exit_codes",
                default=(1,),
                minimum=0,
                maximum=255,
            ),
            timeout_seconds=_integer(
                check.get("timeout_seconds", 15),
                f"{field}.timeout_seconds",
                minimum=1,
                maximum=300,
            ),
            require_stdout=require_stdout,
            healthy_stdout_regex=_optional_regex(
                check.get("healthy_stdout_regex"),
                f"{field}.healthy_stdout_regex",
            ),
            unhealthy_stdout_regex=_optional_regex(
                check.get("unhealthy_stdout_regex"),
                f"{field}.unhealthy_stdout_regex",
            ),
        )

    if kind == "http":
        _only_keys(
            check,
            {
                "kind",
                "name",
                "url",
                "expected_status_codes",
                "timeout_seconds",
            },
            field,
        )
        url = _required_text(check.get("url"), f"{field}.url", maximum=2_000)
        if not url.startswith(("http://", "https://")):
            raise ActionDefinitionError(f"{field}.url must use HTTP or HTTPS")
        return HttpCheck(
            name=_required_text(check.get("name"), f"{field}.name", maximum=128),
            url=url,
            expected_status_codes=_integer_tuple(
                check.get("expected_status_codes"),
                f"{field}.expected_status_codes",
                default=(200,),
                minimum=100,
                maximum=599,
            ),
            timeout_seconds=_integer(
                check.get("timeout_seconds", 10),
                f"{field}.timeout_seconds",
                minimum=1,
                maximum=300,
            ),
        )

    raise ActionDefinitionError(
        f"{field}.kind must be one of: command, http"
    )


def _parse_checks(value: Any, field: str) -> tuple[VerificationCheck, ...]:
    if not isinstance(value, list) or not value:
        raise ActionDefinitionError(f"{field} must be a non-empty JSON array")
    checks = tuple(
        _parse_check(item, f"{field}[{index}]")
        for index, item in enumerate(value)
    )
    names = [check.name for check in checks]
    if len(set(names)) != len(names):
        raise ActionDefinitionError(f"{field} contains duplicate check names")
    return checks


def _execution_spec(value: Any) -> dict[str, Any]:
    if isinstance(value, (bytes, bytearray)):
        value = bytes(value).decode("utf-8")
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError as exc:
            raise ActionDefinitionError("execution_spec is not valid JSON") from exc
    return _mapping(value, "execution_spec")


def action_from_catalog_row(row: dict[str, Any]) -> ActionDefinition:
    """Validate one catalog row and construct an executable definition."""

    executor_type = str(row.get("executor_type") or "").strip().upper()
    if executor_type not in SUPPORTED_EXECUTOR_TYPES:
        raise ActionDefinitionError(
            "executor_type must be one of: "
            + ", ".join(sorted(SUPPORTED_EXECUTOR_TYPES))
        )

    spec = _execution_spec(row.get("execution_spec"))
    _only_keys(
        spec,
        {
            "schema_version",
            "command",
            "command_timeout_seconds",
            "prechecks",
            "postchecks",
            "verification_attempts",
            "verification_delay_seconds",
        },
        "execution_spec",
    )
    _integer(
        spec.get("schema_version"),
        "execution_spec.schema_version",
        minimum=1,
        maximum=1,
    )

    return ActionDefinition(
        action_id=_required_text(row.get("action_id"), "action_id", maximum=128),
        component_id=_required_text(
            row.get("component_id"),
            "component_id",
            maximum=255,
        ),
        target_id=_required_text(row.get("target_id"), "target_id", maximum=128),
        implementation_version=_required_text(
            row.get("implementation_version"),
            "implementation_version",
            maximum=64,
        ),
        executor_type=executor_type,
        command=_required_text(
            spec.get("command"),
            "execution_spec.command",
            maximum=MAX_COMMAND_CHARS,
        ),
        command_timeout_seconds=_integer(
            spec.get("command_timeout_seconds", 60),
            "execution_spec.command_timeout_seconds",
            minimum=1,
            maximum=3_600,
        ),
        precheck_checks=_parse_checks(
            spec.get("prechecks"),
            "execution_spec.prechecks",
        ),
        postcheck_checks=_parse_checks(
            spec.get("postchecks"),
            "execution_spec.postchecks",
        ),
        verification_attempts=_integer(
            spec.get("verification_attempts", 6),
            "execution_spec.verification_attempts",
            minimum=1,
            maximum=30,
        ),
        verification_delay_seconds=_integer(
            spec.get("verification_delay_seconds", 5),
            "execution_spec.verification_delay_seconds",
            minimum=0,
            maximum=300,
        ),
    )


def estimated_max_runtime_seconds(action: ActionDefinition) -> int:
    """Conservative runtime bound used to validate the execution lease."""

    def check_seconds(check: VerificationCheck) -> int:
        return (
            check.timeout_seconds
            if isinstance(check, CommandCheck)
            else check.timeout_seconds + 5
        )

    precheck_seconds = sum(check_seconds(check) for check in action.precheck_checks)
    postcheck_seconds = sum(
        check_seconds(check) for check in action.postcheck_checks
    )
    retry_delays = (
        max(action.verification_attempts - 1, 0)
        * action.verification_delay_seconds
    )
    return (
        action.command_timeout_seconds
        + precheck_seconds
        + action.verification_attempts * postcheck_seconds
        + retry_delays
    )


def validate_action_rows(rows: list[dict[str, Any]]) -> list[str]:
    """Return validation errors for active database definitions."""

    errors: list[str] = []
    seen: set[str] = set()
    for index, row in enumerate(rows):
        action_id = str(row.get("action_id") or f"row {index}")
        if action_id in seen:
            errors.append(f"{action_id}: duplicate active action_id")
            continue
        seen.add(action_id)
        try:
            action_from_catalog_row(row)
        except ActionDefinitionError as exc:
            errors.append(f"{action_id}: {exc}")
    return errors


def enabled_action_ids(rows: list[dict[str, Any]]) -> list[str]:
    return sorted(str(row["action_id"]) for row in rows)
