"""Source-independent checks for an LLM-written investigation SOP.

These checks reject claims that require a live investigation and standalone
shell commands that are not in the traced DAG or administrator confirmations.
They do not prove that every sentence in a generated SOP is correct.
"""

from __future__ import annotations

import re

try:
    from .source_command_analysis import (
        is_read_only_ssh_command,
        placeholder_sop_shell_lines,
        unsafe_sop_shell_lines,
    )
except ImportError:  # Support isolated analysis tests.
    from source_command_analysis import (
        is_read_only_ssh_command,
        placeholder_sop_shell_lines,
        unsafe_sop_shell_lines,
    )


_CURRENT_VERDICT = re.compile(
    r"^\s*(?:#{1,6}\s*)?(?:\*\*)?"
    r"(?:current|actual|live)\s+"
    r"(?:classification|result|status|finding)\b",
    re.IGNORECASE | re.MULTILINE,
)
_VERDICT_VALUE = re.compile(
    r"^\s*(?:\*\*)?(?:classification|verdict)\s*:\s*(?:\*\*)?\s*"
    r"(?:INCONCLUSIVE|MANUAL_REVIEW_REQUIRED|NO_REMEDIATION_REQUIRED)\b",
    re.IGNORECASE | re.MULTILINE,
)
_HOST_MAPPING_CLAIM = re.compile(
    r"^\s*(?:The|This)\s+(?:selected|registered|RCA)\s+"
    r"(?:[A-Za-z]+\s+){0,3}target\b"
    r"[^\n.]{0,140}\b(?:is|was|has been)\s+"
    r"(?:independently\s+)?(?:verified|confirmed)\b",
    re.IGNORECASE | re.MULTILINE,
)
_SHELL_COMMAND = re.compile(
    r"^(?:sudo|kill|pkill|rm|bash|sh|python\d*|nohup|systemctl|"
    r"pgrep|ps|stat|df|uptime|hostname|wc|ls|grep|head|tail|cat)\b"
)


def _standalone_shell_lines(sop: str) -> list[str]:
    """Count executable-looking lines, including Markdown list commands."""
    lines = []
    for line in sop.splitlines():
        candidate = re.sub(r"^[-*]\s+", "", line.strip()).strip("`").strip()
        if _SHELL_COMMAND.match(candidate):
            lines.append(candidate)
    return lines


def sop_quality_issues(
    sop: str,
    *,
    source_commands: list[str],
    administrator_commands: list[str] | None = None,
) -> list[str]:
    """Return actionable reasons to reject an unsupported SOP draft.

    The caller derives source_commands from static DAG analysis and
    administrator_commands from explicit, validated read-only confirmations.
    Neither list may come from the LLM's output.
    """
    issues = []
    if _CURRENT_VERDICT.search(sop) or _VERDICT_VALUE.search(sop):
        issues.append(
            "Do not assign a current classification during onboarding; "
            "give conditional rules for future investigations instead"
        )
    if _HOST_MAPPING_CLAIM.search(sop):
        issues.append(
            "Do not claim the selected target's Airflow host mapping was "
            "verified; list it as an activation prerequisite"
        )

    if placeholder_sop_shell_lines(sop):
        issues.append("Replace shell placeholders with exact source-derived commands")
    if unsafe_sop_shell_lines(sop):
        issues.append("Remove standalone commands that are not read-only diagnostics")

    approved = set(source_commands)
    for command in administrator_commands or []:
        if is_read_only_ssh_command(command):
            approved.add(command)
    observed = _standalone_shell_lines(sop)
    if any(command not in approved for command in observed):
        issues.append(
            "Remove standalone shell commands that are neither traced from "
            "the DAG nor explicitly approved read-only diagnostics"
        )
    if any(command not in observed for command in source_commands):
        issues.append("List every traced read-only DAG command exactly")
    return issues
