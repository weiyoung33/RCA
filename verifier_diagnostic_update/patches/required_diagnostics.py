# RCA_REQUIRED_DIAGNOSTICS_V1
# Inserted into the existing verifier_agent.py; no new runtime import is needed.


class _RcaDiagnosticSelectionError(ValueError):
    """A bounded local repair could not select an authorized diagnostic."""


def _rca_diag_sections(sop):
    """Read numbered SOP prose without treating shell/SQL lines as headings."""
    sections = []
    current = None
    fence = None
    for line in str(sop or "").splitlines():
        marker = re.match(r"^\s*(`{3,}|~{3,})", line)
        if marker:
            token = marker.group(1)[0]
            if fence is None:
                fence = token
            elif fence == token:
                fence = None
        numbered = None if fence else re.match(r"^\s*(\d+)\\?[.)]\s+(.+)$", line)
        if numbered:
            current = {"number": int(numbered.group(1)), "lines": [numbered.group(2)]}
            sections.append(current)
        elif current is not None:
            current["lines"].append(line)
    return sections


def _rca_diag_target(text):
    # Markdown decoration around names is presentation, not part of an ID.
    text = text.lstrip()
    link = re.match(r"\[([^\]]+)\]\(([^)]+)\)", text)
    if link:
        return link.group(2).strip()
    quoted = re.match(r"(['\"`])([^\n]+?)\1", text)
    if quoted:
        return quoted.group(2).strip()
    plain = re.match(r"[A-Za-z0-9_][A-Za-z0-9_.:/?&=%@+\-]*", text)
    return plain.group(0).rstrip(".") if plain else ""


def _rca_diag_payload(text, field):
    """Take only an explicit exact-command/query block, never following prose."""
    cue = re.search(
        r"\b(?:this\s+|the\s+)?exact\s+(?:read[- ]only\s+|diagnostic\s+)?"
        + (r"(?:SELECT\s+)?query" if field == "query" else r"(?:diagnostic\s+)?command")
        + r"\s*:\s*", text, re.I,
    )
    if cue is None:
        return None, ""
    tail = text[cue.end():]
    fenced = re.match(r"\s*(`{3,}|~{3,})[^\n]*\n", tail)
    if fenced:
        close = re.search(r"(?m)^\s*" + re.escape(fenced.group(1)) + r"\s*$", tail[fenced.end():])
        if close is None:
            return None, ""
        body = tail[fenced.end():fenced.end() + close.start()].strip()
        after = tail[fenced.end() + close.end():]
        return body or None, after
    # Legacy one-line quotes can contain SQL string literals or shell quotes.
    # Use the outer pair only when it encloses the whole first line.
    lines = tail.splitlines()
    start = next((i for i, line in enumerate(lines) if line.strip()), None)
    if start is None:
        return None, ""
    first = lines[start].strip()
    quoted = re.fullmatch(r"(['\"`])(.*)\1\.?", first)
    if quoted:
        return quoted.group(2).strip() or None, "\n".join(lines[start + 1:])
    body = [lines[start].strip()]
    end = start + 1
    # Bare legacy commands are one line. A bare SQL block ends at a blank line.
    if field == "query":
        while end < len(lines) and lines[end].strip():
            if re.match(r"^\s*(?:[-*]\s+|If\b|Interpret\b|Evaluate\b|Run\b|Use\b)", lines[end], re.I):
                return None, ""
            body.append(lines[end].strip())
            end += 1
    return "\n".join(body), "\n".join(lines[end:])


def _rca_diag_initial_checks(sop):
    """Resolve only the leading unconditional exact checks, across tool types.

    Stop at interpretation, optional checks or branch instructions. Conditional
    continuation remains with the model; a tool mentioned in a branch is never
    promoted into an unconditional operation by this parser.
    """
    checks = []
    preamble = re.split(r"(?m)^\s*1\\?[.)]\s+", str(sop or ""), maxsplit=1)[0]
    if re.search(r"(?im)\b(?:if|unless|when)\b[^\n]*\b(?:run|execute|begin|step\s*1)\b|"
                 r"\b(?:run|execute|begin|step\s*1)\b[^\n]*\b(?:only\s+if|unless|only\s+after)\b",
                 preamble):
        return checks
    for section in _rca_diag_sections(sop):
        if section["number"] != len(checks) + 1:
            break
        title = section["lines"][0].strip().replace("**", "")
        text = "\n".join([title] + section["lines"][1:])
        run = re.match(
            r"^(?:Run|Use|Execute)\s+(?:the\s+)?`?"
            r"(query_database|run_ssh_command|check_http_endpoint|"
            r"verify_ip_reachability|ping_server|verify_smb_connectivity|"
            r"check_port|check_db_connection)`?(?:\s+tool)?(?=\s|\.)", title, re.I,
        )
        if run is None:
            break
        prefix = re.split(r"\bexact\b", title, maxsplit=1, flags=re.I)[0]
        if re.search(r"\b(?:if|when|unless|optional|after|once|provided)\b", prefix, re.I):
            break
        tool = run.group(1).lower()
        remainder = text[run.end():]
        target_cue = re.match(r"\s+on\s+(?:target\s+)?", remainder, re.I)
        if target_cue is None:
            target_cue = re.match(r"\s*\.\s*Set\s+(?:the\s+)?target\s+to\s+", remainder, re.I)
        if target_cue is None:
            break
        target = _rca_diag_target(remainder[target_cue.end():])
        if not target or not _target_is_in_sop(target, sop):
            break
        check = {"tool": tool, "target": target, "command": "", "query": ""}
        after = ""
        if tool in {"query_database", "run_ssh_command"}:
            field = "query" if tool == "query_database" else "command"
            payload, after = _rca_diag_payload(text, field)
            if payload is None:
                break
            check[field] = payload
            allowed = (_database_query_is_allowed(payload, sop) if field == "query"
                       else _ssh_command_is_allowed(payload, sop))
            if not allowed[0]:
                break
        else:
            after = "\n".join(section["lines"][1:])
            if tool in {"check_port", "check_db_connection"}:
                port = re.search(r"\bport\s*(?:=|:|to)?\s*(\d+)\b", title, re.I)
                if port is None or not 1 <= int(port.group(1)) <= 65535:
                    break
                check["port"] = int(port.group(1))
        checks.append(check)
        # Prose below a check can control later steps, even when the next
        # numbered heading itself starts with an unconditional-looking Run.
        if re.search(r"\b(?:if|when|unless|otherwise|only\s+if|optional|"
                     r"skip|stop|proceed|then|repeat|retry)\b", after, re.I):
            break
    return checks


def _rca_diag_same_check(entry, check):
    fields = ["tool", "target"]
    if check["tool"] == "query_database":
        fields.append("query")
    if check["tool"] == "run_ssh_command":
        fields.append("command")
    if "port" in check:
        fields.append("port")
    return all(
        (_normalized_text(entry.get(key)) == _normalized_text(check.get(key))
         if key in {"query", "command"} else entry.get(key) == check.get(key))
        for key in fields
    )


def _rca_diag_bootstrap(sop, history):
    checks = _rca_diag_initial_checks(sop)
    if len(checks) > MAX_TOOL_STEPS:
        raise _RcaDiagnosticSelectionError(
            "The SOP requires " + str(len(checks)) + " initial checks but "
            "VERIFIER_MAX_TOOL_STEPS is " + str(MAX_TOOL_STEPS) + ". Increase that limit for this SOP."
        )
    for index, check in enumerate(checks):
        if index < len(history):
            if not _rca_diag_same_check(history[index], check):
                # Retain checkpoints from older model-driven runs. Do not run
                # reordered checks over them or silently discard their evidence.
                raise _RcaDiagnosticSelectionError(
                    "Saved diagnostic history does not match the SOP's initial check order. "
                    "Review the checkpoint before starting a fresh investigation."
                )
            continue
        if history and history[-1]["result"].get("status") != "SUCCESS":
            # Give the model the failure; it may follow an authorized fallback.
            break
        print("[VERIFIER DIAGNOSTICS] Running required SOP step " + str(index + 1)
              + ": " + check["tool"] + " on " + check["target"], flush=True)
        result = _execute_tool(check, sop)
        entry = {"step": len(history) + 1, **check, "result": _json_safe(result)}
        if check["tool"] == "query_database":
            entry["query_source"] = "SOP_REQUIRED_STEP"
        else:
            entry["command_source"] = "SOP_REQUIRED_STEP"
        history.append(entry)
        print("[VERIFIER DIAGNOSTICS] Result: " + str(result.get("summary") or result.get("status")), flush=True)
    return checks


def _rca_diag_instruction_problem(instruction, sop, history, checks):
    if not isinstance(instruction, dict):
        return "The decision must be one JSON object."
    if instruction.get("is_final") is True:
        if not history and _sop_requires_diagnostic(sop):
            return "No diagnostic has run. Select the first applicable SOP diagnostic before answering."
        # An attempted failure is evidence of unavailability, not a reason to
        # demand repeatedly executing the same failed check.
        complete_prefix = all(
            index < len(history) and _rca_diag_same_check(history[index], check)
            for index, check in enumerate(checks)
        )
        if not complete_prefix and history and all(
            entry["result"].get("status") == "SUCCESS" for entry in history
        ):
            return "Initial SOP checks remain unexecuted. Select the next required check before answering."
        return ""
    if instruction.get("is_final") is not False:
        return "Set is_final=false and select the next diagnostic, or is_final=true for a completed report."
    tool = instruction.get("tool")
    known = {"query_database", "run_ssh_command", "check_http_endpoint", "check_port",
             "check_db_connection", "ping_server", "verify_ip_reachability",
             "verify_smb_connectivity", "fetch_mlflow_metrics"}
    if not isinstance(tool, str) or tool.strip() not in known:
        return "Select an available SOP diagnostic tool; do not return an empty or unknown tool."
    if not isinstance(instruction.get("target"), str) or not instruction["target"].strip():
        return "Select the diagnostic's exact SOP target."
    field = {"query_database": "query", "run_ssh_command": "command"}.get(tool.strip())
    if field and (not isinstance(instruction.get(field), str) or not instruction[field].strip()):
        return "Copy the exact SOP " + field + "; it must not be empty."
    return ""


def _rca_diag_next_instruction(incident_context, sop, history, checks, repair_state):
    original = _prompt_input(incident_context, sop, history)
    correction = ""
    while True:
        instruction = _call_llm(original + correction, TOOL_DECISION_PROMPT)
        problem = _rca_diag_instruction_problem(instruction, sop, history, checks)
        if not problem:
            return instruction
        if repair_state["used"] >= 2:
            raise _RcaDiagnosticSelectionError(
                "Diagnostic selection could not be completed after two in-attempt corrections. "
                + problem + " No missing measurement is inferred; review this SOP's tool step and model response."
            )
        repair_state["used"] += 1
        print("[VERIFIER DIAGNOSTICS] Correcting premature/invalid decision "
              + str(repair_state["used"]) + "/2: " + problem, flush=True)
        correction = ("\n\nDIAGNOSTIC SELECTION CORRECTION:\n" + problem
                      + "\nThe preceding decision was not accepted and no tool was executed for it. "
                      "Read the actual history and choose the next applicable authorized diagnostic. "
                      "Conditional and optional checks keep their SOP conditions. Never invent a command, "
                      "target, result, or successful check. Return the requested JSON object only.")


def _rca_diag_guard_final(response, history, checks):
    # Refuse a conclusive report if the model left a parsed requirement undone.
    # Diagnostic failures remain the responsibility of the existing normalizer.
    if len(history) < len(checks) or any(
        not _rca_diag_same_check(history[index], check)
        for index, check in enumerate(checks[:len(history)])
    ):
        response = dict(response)
        if response.get("classification") not in {"MANUAL_REVIEW_REQUIRED", "INCONCLUSIVE"}:
            response["classification"] = "INCONCLUSIVE"
        response["recommended_action"] = ""
        response.pop("current_state_assessment", None)
        response["unresolved_questions"] = _text_items(response.get("unresolved_questions")) + [
            "Not every initial required SOP diagnostic has an executed result."
        ]
    return response
