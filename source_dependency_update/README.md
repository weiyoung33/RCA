# Source dependency interpretation for RCA onboarding

This update implements the three investigation-side improvements: variable
dependencies, dynamic SQL/date expressions, and complete collection-based alert
calculations. It is separate from the execution-mode v4 update and works with
that update installed.

## Result for the supplied model-monitoring DAG

The source plan now resolves all three checks without asking an administrator
for `nb_records` or yesterday's date. It follows:

1. Daily confidence summaries and the number of returned days.
2. The dependent lot-query limit of that day count plus one.
3. The date-to-lot-count lookup, including the source default of zero.
4. The minimum-lot filter, the first seven qualifying records in source order,
   and the unweighted mean of their daily averages.
5. Yesterday's observation gate, the valid-mean gate and the inclusive alert
   comparison of mean <= 0.8.

One qualifying day is allowed by this particular source; the generator does
not invent a two-day requirement. No production or no qualifying measurements
does not establish model health. Source constants and confirmed Airflow values
remain distinct from results that must be calculated during investigation.

## General supported data flow

There is no DAG-name, table-name, variable-name or threshold allowlist.
Supported operations include result selection, unpacking, indexing, slices,
numeric arithmetic, comparisons, conditional values, dictionary lookups,
comprehensions, list accumulation over result rows and simple pure helper
returns. F-strings, concatenation, simple format construction, and positional
or named SQL value bindings can carry supported date/dependency expressions.

Source code is parsed as syntax. It is never imported or run. The expression
model has a bounded sample evaluator; it cannot run source functions, SQL,
SSH commands, notifications or writes. Unsupported helpers, cross-task inputs
and expressions stay explicit review items.

## How SQL stays compatible with the current Verifier

The generated SOP still contains exact, literal read-only SELECT statements.
No Verifier, executor, credential registry, database schema or tool contract is
changed by this update.

- Relative Python date expressions become database-calendar expressions in the
  current-state diagnostic query. The SOP explicitly identifies this clock
  policy; it does not assume the Airflow host and database clocks are equal.
- An ordered query with a supported runtime LIMIT is retrieved without that
  final limit, then its original computed row limit is applied before using
  the records. It is not replaced with an arbitrary fixed number.
- Require a complete, untruncated result. For the supplied lot query, the SQL
  window contains at most 30 grouped calendar dates. Larger result sets can
  encounter the Verifier's existing evidence cap and must remain inconclusive
  rather than inventing missing values.
- Dynamic identifiers, unordered runtime limits, partial quoted-value
  substitutions and unsupported bindings are not silently rewritten.

The Verifier follows the generated SQL and calculation instructions through
its existing workflow. The structured sample evaluator verifies the plan's
math; it does not replace the live Verifier or make a live diagnosis here.

New data-flow drafts do not wait for optional AI explanations. Their plan and
SOP are built deterministically. Existing simple SSH and literal-SQL rendering
is retained.

## Install

Extract `source_dependency_update` inside the existing application project.
Stop the backend, then run from the **application project root**:

```powershell
python .\source_dependency_update\scripts\install_source_dependencies.py .
python .\source_dependency_update\scripts\install_source_dependencies.py . --apply
```

For installation directly on your Linux server:

```bash
cd /apps/pythonproj/rca_home || exit
/apps/pythonproj/rca_env/bin/python source_dependency_update/scripts/install_source_dependencies.py . --apply
```

The installer prepares the edits, checks destination access and stages all
files before replacing application files. It backs up every destination and
installs the supporting module before adding its import. It preserves your
existing source-analyser features and execution-mode code. A repeated run
checks completion and can restore a missing supporting module.

It updates:

- `backend/app/evidence_plan.py` — adds the dependency builder, rendering hook
  and canonical validation of the new plan metadata.
- `backend/app/source_dependencies.py` — new reusable analysis/rendering module.
- `backend/app/onboarding_agent.py` — skips optional model explanations for
  these deterministic drafts when that existing integration point is present.

The package deliberately patches your existing files instead of supplying old
full-file replacements. If installing locally and uploading to Linux, upload
**all three resulting files from your installed project**, including the new
`source_dependencies.py`, to `/apps/pythonproj/rca_home/backend/app/`.

Confirm imports on Linux before starting the backend:

```bash
cd /apps/pythonproj/rca_home/backend || exit
/apps/pythonproj/rca_env/bin/python -c "import app.source_dependencies; from app.evidence_plan import build_plan; print('Source dependency imports OK')"
```

Restart the backend. Regenerate affected drafts and review their SOPs through
the normal onboarding process. Saved procedures are not automatically changed.
The example under `examples/` is an offline generated draft, not production
diagnostic evidence.

## Verification

After installation, run from the application project root:

```powershell
python -m unittest discover -s .\source_dependency_update\tests -v
```

Local verification passed 36 focused tests, including an onboarding response
without a model/database call and 100 generated datasets compared with an
independent implementation of the supplied source's selection/math. The same
tests and 54 earlier regression tests passed together on the earlier complete
analyser variant (90 tests total). Installer checks passed against both
available analyser versions, including preview, directory-write failure,
v4-code preservation, missing-module repair and rollback. Python source was
checked against Python 3.9 grammar.

No live production SQL, SSH execution, database migration or full deployed
application test was performed. Keep the normal read-only target and result
validation checks in the existing runtime.

## Rollback

Use the backup directory printed by the installer. Preview, then apply:

```powershell
python .\source_dependency_update\scripts\rollback_source_dependencies.py . .\source_dependency_backup_YOUR_TIMESTAMP
python .\source_dependency_update\scripts\rollback_source_dependencies.py . .\source_dependency_backup_YOUR_TIMESTAMP --apply
```

Rollback refuses to overwrite subsequent file edits. It restores source files
only and does not change incident or catalog records.
