"""Remove only the code injected by install_investigation_features.py v3.

Run from the application project root with Python 3.9 or newer:
    python rollback_without_backups.py .
    python rollback_without_backups.py . --apply

This is a strict inverse of that installer's five integration patches. It
refuses unexpected shapes instead of replacing your files with older copies.
"""

import argparse
import ast
from datetime import datetime, timezone
from pathlib import Path
import shutil
import sys
import uuid


ADDED = (
    "backend/app/diagnostic_contract.py",
    "backend/app/investigation_api.py",
    "backend/app/investigation_runs.py",
    "backend/app/sop_test_service.py",
    "agents/diagnostic_contract.py",
    "agents/diagnostic_runner.py",
    "frontend/src/components/InvestigationHistory.vue",
    "frontend/src/components/SopTestPanel.vue",
    "frontend/src/services/diagnosticApi.js",
    "migrations/investigation_runs.sql",
)

VERIFIER = "agents/verifier_agent.py"
PIPELINE = "agents/pipeline_runner.py"
MAIN = "backend/app/main.py"
INCIDENT = "frontend/src/views/IncidentDetailView.vue"
ONBOARDING = "frontend/src/views/AdminOnboardingView.vue"
MODIFIED = (VERIFIER, PIPELINE, MAIN, INCIDENT, ONBOARDING)


def remove_once(source, old, new, label, expected=1):
    found = source.count(old)
    if found != expected:
        raise ValueError("Unexpected " + label + " shape: expected " + str(expected) +
                         " occurrences, found " + str(found) + ". No files changed.")
    return source.replace(old, new)


def revert_verifier(source):
    source = remove_once(source,
        '    *,\n    tool_executor=None,\n    investigation_context: str = "",\n',
        '', 'Verifier signature')
    source = remove_once(source,
        '\n    # RCA_INVESTIGATION_RUNS_V1\n'
        '    _diagnostic_executor = tool_executor if tool_executor is not None else _execute_tool\n',
        '', 'Verifier executor hook')
    source = remove_once(source, '_diagnostic_executor(', '_execute_tool(',
                         'Verifier tool calls', expected=2)
    source = remove_once(source,
        '(_prompt_input(incident_context, raw_db_sop, history) + '
        '"\\n\\nRUN CONTEXT:\\n" + investigation_context)',
        '_prompt_input(incident_context, raw_db_sop, history)',
        'Verifier injected model context', expected=2)
    ast.parse(source)
    return source


def revert_pipeline(source):
    source = remove_once(source,
        '    # RCA_INVESTIGATION_RUNS_V1\n'
        '    if __package__:\n'
        '        from .diagnostic_runner import process_diagnostic_run\n'
        '    else:\n'
        '        from diagnostic_runner import process_diagnostic_run\n'
        '    diagnostic_processed = process_diagnostic_run()\n'
        '    processed = processed or diagnostic_processed\n',
        '', 'pipeline integration')
    ast.parse(source)
    return source


def revert_main(source):
    source = remove_once(source,
        '# RCA_INVESTIGATION_RUNS_V1\n'
        'from .investigation_api import register_investigation_routes\n'
        'register_investigation_routes(app, linked_engineer, current_admin)\n\n',
        '', 'backend route registration')
    ast.parse(source)
    return source


def revert_incident(source):
    source = remove_once(source,
        "import InvestigationHistory from '../components/InvestigationHistory.vue'\n",
        '', 'history component import')
    source = remove_once(source,
        '<!-- RCA_INVESTIGATION_HISTORY_V1 -->\n'
        '          <InvestigationHistory :incident-id="incident.incident_id" '
        ':user="linkUser" :enabled="linkUserAllowed" />\n        ',
        '', 'history component insertion')
    return source


def revert_onboarding(source):
    source = remove_once(source,
        "import SopTestPanel from '../components/SopTestPanel.vue'\n",
        '', 'SOP test component import')
    source = remove_once(source,
        '\n          <!-- RCA_SOP_TEST_PANEL_V1 -->\n'
        '          <SopTestPanel :draft="bundle" '
        ':source-review="usesDagSource ? structuredInput : null" '
        ':ready="assistantReady || canReviewCurrentDraft" />\n',
        '', 'SOP test component insertion')
    return source


REVERT = {
    VERIFIER: revert_verifier,
    PIPELINE: revert_pipeline,
    MAIN: revert_main,
    INCIDENT: revert_incident,
    ONBOARDING: revert_onboarding,
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('project_root', type=Path)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    root = args.project_root.resolve()
    try:
        # Preflight *every* patch before changing any app file.
        updates = {}
        for relative, transform in REVERT.items():
            path = root / relative
            if not path.is_file():
                raise ValueError('Required file missing: ' + relative)
            old = path.read_text(encoding='utf-8')
            new = transform(old)
            if new == old:
                raise ValueError('Nothing to remove from ' + relative)
            updates[relative] = new
        present = [name for name in ADDED if (root / name).is_file()]
        print('Prepared to restore the five existing source files:')
        for relative in MODIFIED:
            print('  ' + relative)
        print('Added feature files currently present:', len(present))
        for relative in present:
            print('  ' + relative)
        if not args.apply:
            print('Read-only preview. Run again with --apply to make these changes.')
            return

        stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
        archive = root / 'rollback_safety_snapshots' / ('without_backups_' + stamp + '_' + uuid.uuid4().hex[:8])
        for relative in MODIFIED + ADDED:
            path = root / relative
            if path.is_file():
                saved = archive / 'before' / relative
                saved.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(path, saved)
        try:
            for relative, content in updates.items():
                with (root / relative).open('w', encoding='utf-8', newline='') as output:
                    output.write(content)
            for relative in present:
                (root / relative).unlink()
        except BaseException:
            for relative in MODIFIED + ADDED:
                saved = archive / 'before' / relative
                if saved.is_file():
                    target = root / relative
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(saved, target)
            raise
        print('Rollback complete. Safety copy:', archive)
        print('Database investigation_runs table left intact.')
    except (OSError, UnicodeError, ValueError, SyntaxError) as exc:
        parser.exit(1, 'Rollback stopped: ' + str(exc) + '\n')


if __name__ == '__main__':
    main()
