# Admin execution mode with Airflow template resolution — v4

This update adds **Investigate with approved execution** to the existing
onboarding page. It supports both pasted DAGs and manual onboarding, and upgrades
the v1, v2 and v3 execution-mode packages in place.

## Fix for templated SSHOperator commands

Startup commands using `{{ var.value.variable_name }}` or
`{{ var.value['variable_name'] }}` are now traced as configured command inputs.
This works for arbitrary variable names, including references within Python
string concatenation. The form asks once for missing deployed values, reuses
values already supplied, and fills the startup command after they resolve.
Pasted code, template calls and external scripts are never executed during
extraction. Other Jinja expressions remain explicit review items; unresolved
templates are not copied into an executable action.

The reported `flipchip_execute_linux_watchdog` source is included as a regression
fixture. Its startup operation needs these three deployed values:

- `flipchip_proj_pythonvenvpath`: the interpreter value used by that command.
- `flipchip_proj_scriptpath`: the script-directory value.
- `flipchip_proj_linux_watchdog`: the monitored script-name value.

The command joins directory and filename directly. Preserve the deployed
directory's trailing slash where required; the extractor does not insert path
separators or guess deployed paths. After values resolve, it fills the exact
`nohup ... >/dev/null 2>&1 &` command and, when the filename matches, the full
process path. The existing process-count and RAM conditions remain in the
approval-required action.

## Automatic action prefill

After you paste a DAG and choose execution mode, the form reads its Python
syntax automatically. A single detected action prefills the editable form.
If several distinct actions are detected, choose the one to register for this
component. Source line, connection, conditions and missing values appear beside
each suggestion. No model call, source import, database query or remote command
is needed for extraction.

The extractor handles literal commands, common string construction, deployed
Airflow Variables, configuration dictionaries, bounded literal loops, called
helpers and runtime PIDs traced back to `pgrep`. It is a general source tracer;
it has no component-name or DAG-name allowlist. Unsupported expressions remain
reviewable gaps rather than guessed commands.

- Existing deployed values and the server selection are reused.
- Missing variable inputs accept plain text such as `main.py` or numbers such
  as `15`; you do not need to add JSON quotes in the action form.
- Runtime PID commands become process actions which discover processes again
  at execution. A stale source PID is not saved into those actions.
- A following startup command is combined with the stop operation when the
  source scope and conditions support the pairing.
- A trigger of another Airflow DAG is shown with an optional **Add source for
  [DAG ID]** field. Paste that restart DAG to prefill the startup command. Manual
  command entry remains available when the source is unavailable.
- Source-derived process-count, RAM and CPU conditions are carried into the
  health check when supported. Other conditions need a reviewed health check.
- Refreshing suggestions preserves fields you edited. Older responses are
  discarded; changing the DAG asks you to reapply updated source values.

Suggestions are not activated automatically. Review them in the existing
draft and activation flow.

## When the restart command is in another DAG

1. Expand **Add source for [DAG ID]** beside the detected dependency.
2. Paste the restart DAG or the snippet containing its startup operation.
3. The form automatically uses one unambiguous SSH startup command. If several
   commands exist, choose **Use this startup command** beside the appropriate
   source line. Different source connections and conditional startup operations
   are offered for review rather than silently rebound to the selected server.
4. Any needed Airflow Variables appear in the same deployed-values inputs.
   Values already supplied are reused. If the monitor uses a filename and the
   startup command contains that same filename at an absolute path, the full
   process path is filled too. An unset variable is not guessed from another
   command.
5. Review the resulting action and activate through the existing approval flow.

Wrong-DAG and syntax errors appear beside the optional source field. They do
not discard the main action or prevent completing it manually. Startup choices
retain their source DAG, line and connection. Refreshing source keeps edited
commands and process paths. Related source is included in the review input;
no additional connection or credential entry is introduced.

This extracts an SSH startup command from supplied source. It does not call an
Airflow API, run the pasted DAG or fetch inaccessible scripts. A shell launcher
can be selected without uploading the implementation of that external script.

## What the administrator can choose

- **Start or restart a script:** discover matching processes at runtime, stop
  them, then run the reviewed startup command. Matching uses an exact absolute
  script-path argument and an optional owner.
- **Remove excess script processes:** keep the configured number of oldest
  matching instances; signal only the extras. Zero instances is not a condition
  this action can repair.
- **Stop matching script processes:** discover the reviewed process scope and
  stop it without inventing a startup command.
- **Reviewed custom command:** store the administrator's exact shell command
  with its health check. This supports service managers, existing deployment
  scripts and other approved operations without a DAG-specific code change.
- **Choose an existing action:** reuse an ACTIVE action for the same component
  and server.

The generated SOP is based on **administrator-reviewed action health checks**.
It is labelled accordingly. Pasted source is supporting context; source lines
such as `kill_command = f"kill {pid}"` do not become executable diagnostics.
The normal investigate-only source-analysis path is preserved.

## Installation on your Windows project

1. Extract this ZIP so the `executor_mode_update` folder is inside your existing
   `rca-agent-dashboard` folder. Do not copy its backend/frontend files directly
   over the application.
2. Stop the backend, frontend and remediation executor while applying the update.
3. From the existing **application project root**, preview the changes:

   ```powershell
   python .\executor_mode_update\scripts\install_executor_mode.py .
   ```

4. Apply:

   ```powershell
   python .\executor_mode_update\scripts\install_executor_mode.py . --apply
   ```

5. Restart the backend and frontend. Start/restart your existing remediation
   executor from the project root:

   ```powershell
   python -m agents.remediation_executor
   ```

   Keep `pipeline_runner.py` running for diagnosis. The remediation executor is
   a separate process; adding an action does not make the pipeline execute it.

The installer prepares every change before writing and backs up all existing
destinations in one `executor_mode_backup_...` folder. If a supplied integration
point differs, it stops before writes and names the file needing review.
It patches the existing files rather than replacing them with older copies.

### Requirements

- Your current source-onboarding schemas and database-backed action registry.
- Existing `remediation_action_catalog.execution_spec` support (catalog schema
  version 1). No new database migration is needed for this update.
- The selected SSH target needs an active `EXECUTOR_REMEDIATION` credential.
  Existing configured credentials are reused; the action form never asks for
  the server twice. New-server credentials remain in Step 2's secure form.
- Built-in process actions run on Linux with `/proc` and the configured Python
  executable. Choose a custom command for other operating systems or for a
  managed service whose workers have a more complex topology.

## Using it

1. Paste the DAG or enter manual component details.
2. Choose the server once.
3. Select **Investigate with approved execution**.
4. Review the action prefilled from the DAG, choose a detected action, or select
   an existing one. Complete only missing deployed values or command details.
   Manual action entry is still available. Advanced settings are optional.
5. Generate the draft. Review its current-state health checks and the exact
   catalog command shown in the final review.
6. Confirm the action definition and activate. Activation atomically registers
   the action as ACTIVE, approval-required, and links the component to it.
   It does not run the action.
7. For an already registered component, expand **Already registered?** and
   choose the update option. This replaces its SOP/action link and retains old
   catalog actions and incident history. Finish or cancel active remediation
   requests first.
8. On a VERIFIED incident, request and approve the registered remediation using
   the existing incident workflow. The Executor repeats the health check before
   acting and checks health afterward. New catalog rows are picked up by the
   existing worker's polling loop.

Existing action IDs are never overwritten. To revise a command, use a new ID;
the generated implementation version also changes with its command/checks.

## Health checks

Manually entered process actions default to an expected process-count check.
Extracted actions also retain supported source eligibility conditions. Review
the generated check before activation; process presence alone does not assess
progress or HTTP health.

For a condition that could not be translated, use the **health check override**.
Enter a read-only command that prints a clear
status such as `OK` or `RESTART_REQUIRED`, then enter those two full-output
patterns. The same check runs before and after remediation. A healthy result
skips execution; an ambiguous result prevents it.

For the supplied watchdog flow, extraction retains the single-process and
system-RAM-at-least-50% conditions. Its source Python environment is reused for
the `psutil` measurement. Paste the restart DAG in the optional field to fill
its startup command; enter it directly if that source is unavailable. Do not
enter a PID: the process action discovers it when execution happens.

Source conditions now read, for example: “Exactly one matching process is
running; Server RAM usage is at least 50%; PID discovery confirms exactly one
match.” The two process observations remain distinct and the execution policy
keeps both conditions.

This is a reviewed action definition, not an attempt to replay every statement
in the production DAG. SQL logging writes and notification sends are not
converted into SSH remediation candidates. Source-local commands are identified
as running on the Airflow worker; verify their suitability for the selected
RCA server before registering them.

Custom health checks should print interpretable output on unhealthy results
too. Exit code 1 is a reviewed unhealthy outcome, while unexpected errors,
missing required output and truncation are inconclusive.

## Execution behavior

- The Verifier remains read-only and recommends only the registered action ID.
- Every execution still requires incident approval.
- The executor checks the component, target and implementation version using
  the existing catalog/queue workflow.
- A target lock serializes RCA actions from multiple executor instances.
- Built-in process actions recheck process identity before signalling. They
  use stable PID handles when the host supports them, otherwise an immediate
  identity recheck. Older kernels still have a small PID race; this is not an
  absolute guarantee against every concurrent host change.
- TERM is the default. KILL is an explicit administrator choice. There is no
  silent escalation from TERM to KILL.
- If the selected processes do not exit, the startup command is not run.
- A matching process appearing before startup stops a duplicate start attempt.
- The existing queue records failures and uncertain results; this update does
  not automatically replay a timed-out state-changing command.

The supplied Airflow DAG already contains active kill-and-restart behavior.
Its non-waiting restart trigger is not proof of recovery. Coordinate which
controller owns recovery; the RCA target lock cannot lock an independent
Airflow action. A staging script is the appropriate first execution test.

## Files changed

Patched in place:

- `backend/app/schemas.py`
- `backend/app/onboarding_agent.py`
- `backend/app/onboarding_service.py`
- `frontend/src/views/AdminOnboardingView.vue`
- The current executor module containing `run_registered_action`
- Its `RemediationDatabase` module, to retain uncertain execution outcomes in
  `MANUAL_REVIEW` rather than making a repeat request immediately available

Added:

- `backend/app/managed_actions.py`
- `backend/app/managed_process.py`
- `backend/app/action_candidates.py`
- `frontend/src/components/ManagedActionForm.vue`
- `agents/managed_executor_lock.py`

The installer does not replace `action_registry.py`, the Verifier, the pipeline
runner, authentication, database settings or existing incident UI.

## Local verification

```powershell
python -m unittest discover -s .\executor_mode_update\tests -v
node .\executor_mode_update\tests\test_action_form.mjs
```

82 Python tests passed in the local Linux environment. The tests mock process signals
and restarts; the only real process diagnostic is a read-only inventory probe.
Linux-only inventory tests are skipped on Windows. Additional checks covered
the existing catalog execution-spec schema, fresh installation and upgrade
from v1, v2 and v3, rollback, Python 3.9 grammar compatibility, and JavaScript syntax/state
flow. The extraction route was tested without a database or model call.
The Node state test reads the component's current setup script and checks prefill,
preserved edits, stale responses, source refresh, linked startup selection and
extraction failures. The Python tests also exercise the request-to-extraction-
to-catalog-spec path with related source and the original RAM condition, including
the exact reported SSHOperator command with its Airflow Variable templates.
No live MySQL transaction, production SSH execution or full frontend build was
performed here. Run your normal frontend build after installation.

## Rollback

Keep the installer-created backup. Preview restoration, then add `--apply`:

```powershell
python .\executor_mode_update\scripts\rollback_executor_mode.py . .\executor_mode_backup_YOUR_TIMESTAMP
python .\executor_mode_update\scripts\rollback_executor_mode.py . .\executor_mode_backup_YOUR_TIMESTAMP --apply
```

Rollback refuses to overwrite source files edited after installation. It does
not delete catalog records or incident history. Review registered action status
separately if you stop using an action.
