# Required diagnostic execution fix

The error `The Verifier returned a final answer without the SOP-required diagnostic`
is raised by the Verifier's own scheduling code when the model finalizes with
an empty tool history. It is not a database error. Scheduled retries previously
repeated the same model decision without correcting it.

The old shortcuts recognize only a narrow consecutive-SSH format and a single
database SELECT. For example, an SOP containing three required SELECTs does
not match the single-query shortcut. Other formatting can also leave execution
entirely to the model, exposing the premature-final failure.

## Install

Extract this ZIP in your existing application root, so both of these exist:

```
rca-agent-dashboard/
  agents/verifier_agent.py
  verifier_diagnostic_update/
    scripts/install_required_diagnostics.py
    patches/required_diagnostics.py
    tests/test_required_diagnostics.py
    README.md
```

From the application root on Windows:

```powershell
python .\verifier_diagnostic_update\scripts\install_required_diagnostics.py .
python .\verifier_diagnostic_update\scripts\install_required_diagnostics.py . --apply
```

On your Linux deployment:

```bash
cd /apps/pythonproj/rca_home
/apps/pythonproj/rca_env/bin/python verifier_diagnostic_update/scripts/install_required_diagnostics.py .
/apps/pythonproj/rca_env/bin/python verifier_diagnostic_update/scripts/install_required_diagnostics.py . --apply
```

The first command previews. The second patches the existing file atomically and
makes a timestamped `.before_required_diagnostics_*.bak` backup. It refuses an
unrecognized integration layout before replacing source. Running it again is
safe and reports “Already installed.” Do not replace your whole Verifier with
an older reference copy.

**Only the existing `agents/verifier_agent.py` runtime file changes.** The helper
is inserted into that file; there is no new runtime module to upload. Existing
tools, connection settings such as `use_pure=True`, current-state scope changes,
action authorization, public entry points and evidence normalization are kept.
No backend, frontend, executor, database migration or SOP replacement is required.

If you install on Windows and deploy by SFTP, upload the resulting application
`agents/verifier_agent.py` to `/apps/pythonproj/rca_home/agents/verifier_agent.py`.
Do not upload `__pycache__` or backup files. Restart **pipeline_runner.py** using
your existing stop/start procedure; restarting the backend alone does not reload
this agent code.

## Behavior

- Resolve the leading unconditional numbered diagnostic checks from the SOP.
  SQL and SSH checks can be mixed; several required SELECTs are supported.
  Quoted and unquoted targets, fenced commands/queries, legacy bare blocks and
  the inline “Set the target to ... exact query ...” form are recognized.
  Simple explicit HTTP/reachability/port checks are supported too.
- Execute those exact checks through the existing tool dispatcher before asking
  the model for its report. SQL is not rewritten and script/host/table names are
  not hardcoded. The usual authorization checks still apply.
- Stop automatic progression at optional checks, interpretation steps or explicit
  conditional continuation. The model selects those subsequent steps using the
  actual results. A diagnostic failure is returned to the model for an authorized
  failure branch rather than forcing the next normal check.
- Preserve the configured tool-step budget. Invalid model decisions do not create
  fake `UNKNOWN_TOOL` history entries or spend diagnostic steps. Too many initial
  required checks produce a specific tool-limit finding.
- Reuse matching saved results on a scheduled retry. A changed/conflicting
  initial checkpoint is reported for review; it is not silently discarded.
- For layouts still handled by the model, a premature final answer or empty tool
  selection receives up to **two corrections within that attempt**, using the
  same history. Normal decisions add no extra model calls. A recognized sequence
  of three initial checks needs only the final model call after those checks.
- If the model still cannot select a diagnostic, save an explicit **INCONCLUSIVE**
  diagnostic-selection finding with the missing evidence. Do not recycle this
  identical selection failure through scheduled retries. This is not a successful
  investigation: the report states what could not run and requires review.
- Real model timeouts, unreadable completions and service failures continue through
  the existing retry/backoff path with completed tool history attached.

Missing required checks cannot yield a healthy or executable-remediation result.
A supported abnormal condition can still require manual review while other
checks remain unavailable; the report retains those gaps. Existing accepted
limited-coverage and current-state rules remain in the installed normalizer.

This is a general scheduling repair, not a universal natural-language SOP
interpreter. Unrecognized or conditional layouts still use model selection;
they are not flattened into an unconditional list. The update does not repair
unavailable targets, bad credentials, SQL errors, missing SOP commands, endpoint
failures or a model-service outage. It also does not change classification
precedence in an existing SOP.

## Validate

1. Run a new testcase with a simple one-query or one-command SOP.
2. Run `flipchip_monitor_ml`, which requires all three SELECT checks.
3. Run a conditional SOP, such as the stored-warning report: its details query
   should run only for the positive-count branch.
4. Check the pipeline log for:

```
[VERIFIER DIAGNOSTICS] Running required SOP step 1: query_database on FLIPCHIP_DB
[VERIFIER DIAGNOSTICS] Result: ...
```

For an invalid model decision, the log includes:

```
[VERIFIER DIAGNOSTICS] Correcting premature/invalid decision 1/2: ...
```

The saved report must cite the actual tool results, and its checklist must show
the executed checks. Existing `AWAITING_VERIFICATION` incidents with a future
`next_attempt_at` remain scheduled; their next due attempt uses the updated code
after the pipeline runner restarts. Rows already exhausted to `ERROR` and old
saved reports are not automatically reset or rewritten. Validate a new testcase
before requeueing old incidents. Do not delete the retry table to install this fix.

Optional read-only status query:

```sql
SELECT r.incident_id, i.pipeline_status, r.failure_count,
       r.next_attempt_at, r.lease_expires_at, r.last_error
FROM incident_verification_retries AS r
JOIN live_incidents AS i ON i.incident_id = r.incident_id
ORDER BY r.incident_id DESC;
```

Offline regression tests from the application root:

```powershell
python -m unittest discover -s verifier_diagnostic_update/tests -v
```

Tests stub all model, SSH, HTTP and database access. Validation uses Python 3.12
with Python 3.9 syntax checks; it does not contact your production services or
claim a live model/SSH/database test. Source settings and existing tool functions
are checked for preservation. The package also supports the older structured
Verifier with the database-only bootstrap.
