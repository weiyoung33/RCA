"""Add source dependency analysis to an existing RCA backend (Python 3.9+).

Preview: python source_dependency_update/scripts/install_source_dependencies.py .
Apply:   python source_dependency_update/scripts/install_source_dependencies.py . --apply
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile
from datetime import datetime

MARKER='RCA_SOURCE_DATAFLOW_V1'
MODULE='backend/app/source_dependencies.py'
PLAN='backend/app/evidence_plan.py'
AGENT='backend/app/onboarding_agent.py'


def update_source(source):
    if MARKER in source: return source
    tree=ast.parse(source)
    classes={v.name:v for v in tree.body if isinstance(v,ast.ClassDef)}
    functions={v.name:v for v in tree.body if isinstance(v,ast.FunctionDef)}
    required={'build_plan','validate_plan','render_sop','coverage_review','onboarding_review'}
    if not required.issubset(functions) or 'PlanBuilder' not in classes:
        raise ValueError('The current source-onboarding evidence_plan.py is required; missing integration points')
    methods={v.name for v in classes['PlanBuilder'].body if isinstance(v,ast.FunctionDef)}
    if not {'expression','statements','merged','bind','add_rule','build','unknown','cite'}.issubset(methods):
        raise ValueError('PlanBuilder has changed; review this current file before applying the update')
    edits=[]
    start=functions['build_plan'].lineno-1
    edits.append((start,'''
try:
    from .source_dependencies import builder_class, render_dependency_sop
except ImportError:
    from source_dependencies import builder_class, render_dependency_sop
PlanBuilder = builder_class(PlanBuilder)

'''))
    render=functions['render_sop']
    first=render.body[0]
    insertion=first.end_lineno if isinstance(first,ast.Expr) and isinstance(first.value,ast.Constant) and isinstance(first.value.value,str) else render.lineno
    edits.append((insertion,'''    dependency_sop = render_dependency_sop(plan, dag_id)
    if dependency_sop is not None:
        return dependency_sop
'''))
    validation=functions['validate_plan']
    canonical=[v for v in ast.walk(validation) if isinstance(v,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='canonical' for t in v.targets)]
    if len(canonical)!=1: raise ValueError('Cannot locate the canonical plan validation; no files changed')
    edits.append((canonical[0].end_lineno,'''    if canonical.get("dataflow") != plan.get("dataflow"):
        raise ValueError("The data flow differs from the canonical source derivation.")
'''))
    lines=source.splitlines(keepends=True)
    for position,text in sorted(edits,reverse=True): lines.insert(position,text)
    result=''.join(lines)+'\n# '+MARKER+'\n'
    ast.parse(result,feature_version=(3,9))
    compile(result,'evidence_plan.py','exec')
    return result


def update_agent(source):
    marker=MARKER+'_EXPLANATIONS'
    if marker in source: return source
    tree=ast.parse(source)
    function=next((v for v in tree.body if isinstance(v,ast.FunctionDef) and v.name=='_call_source_sop'),None)
    if function is None: return source
    candidates=[v for v in ast.walk(function) if isinstance(v,ast.If) and 'confirmation_questions' in ast.unparse(v.test) and 'unknowns' in ast.unparse(v.test)
                and any(isinstance(n,ast.Call) and isinstance(n.func,ast.Name) and n.func.id=='_post_llm' for n in ast.walk(v))]
    if len(candidates)!=1: return source
    test=candidates[0].test
    lines=source.splitlines(keepends=True)
    offsets=[0]
    for line in lines: offsets.append(offsets[-1]+len(line))
    start=offsets[test.lineno-1]+test.col_offset
    end=offsets[test.end_lineno-1]+test.end_col_offset
    condition=source[start:end]
    result=source[:start]+'('+condition+') and not plan.get("dataflow", {}).get("active")'+source[end:]
    message='    explanation_status = "Not requested while source confirmations are incomplete."'
    if result.count(message)==1:
        result=result.replace(message,message+'\n    if plan.get("dataflow", {}).get("active"):\n        explanation_status = "Source calculations were traced and rendered without a model call."',1)
    result+='\n# '+marker+'\n'
    compile(result,'onboarding_agent.py','exec')
    return result


def prepare(root):
    payload=Path(__file__).resolve().parents[1]
    if root==payload: raise ValueError('Choose the application project root, not the source_dependency_update folder')
    plan=root/PLAN
    for relative in (PLAN,'backend/app/dag_source_analysis.py','backend/app/source_command_analysis.py'):
        if not (root/relative).is_file(): raise ValueError('Required application file is missing: '+relative)
    old=plan.read_text(encoding='utf-8-sig').replace('\r\n','\n')
    module=(payload/MODULE).read_bytes()
    ast.parse(module.decode('utf-8'),feature_version=(3,9))
    existing=root/MODULE
    if MARKER in old:
        if existing.exists() and (not existing.is_file() or existing.read_bytes()!=module):
            raise ValueError('The installed dependency module differs from this package; review its edits before replacement')
        files={} if existing.exists() else {MODULE:module}
    else:
        if existing.exists(): raise ValueError('An unrecognised source_dependencies.py already exists; review it before replacement')
        # New supporting module is written before its import is added to the app.
        files={MODULE:module,PLAN:update_source(old).encode('utf-8')}
    agent=root/AGENT
    if agent.is_file():
        original=agent.read_text(encoding='utf-8-sig').replace('\r\n','\n')
        updated=update_agent(original)
        if updated!=original: files[AGENT]=updated.encode('utf-8')
    return files


def apply(root,files):
    staged={}
    try:
        for relative,content in files.items():
            destination=root/relative
            if not os.access(destination.parent,os.W_OK|os.X_OK):
                raise ValueError('Destination directory is not writable: '+str(destination.parent))
            handle,path=tempfile.mkstemp(dir=destination.parent,prefix='.rca-dataflow-stage-')
            staged[relative]=path
            with os.fdopen(handle,'wb') as stream: stream.write(content)
            reference=destination if destination.exists() else root/PLAN
            shutil.copymode(reference,path)
            if hasattr(os,'geteuid') and os.geteuid()==0:
                identity=reference.stat()
                os.chown(path,identity.st_uid,identity.st_gid)
        backup=root/('source_dependency_backup_'+datetime.now().strftime('%Y%m%d_%H%M%S_%f'))
        backup.mkdir()
        manifest=[]
        for relative,content in files.items():
            destination=root/relative
            if destination.exists():
                saved=backup/relative;saved.parent.mkdir(parents=True,exist_ok=True)
                shutil.copy2(destination,saved)
            manifest.append({'path':relative,'existed':destination.exists(),'installed_sha256':hashlib.sha256(content).hexdigest()})
        (backup/'manifest.json').write_text(json.dumps(manifest,indent=2),encoding='utf-8')
        written=[]
        try:
            for relative in files:
                os.replace(staged[relative],root/relative)
                written.append(relative)
        except Exception:
            for relative in reversed(written):
                saved=backup/relative
                if saved.exists(): shutil.copy2(saved,root/relative)
                else: (root/relative).unlink()
            raise
        return backup
    finally:
        for path in staged.values():
            if os.path.exists(path): os.unlink(path)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('project_root',type=Path)
    parser.add_argument('--apply',action='store_true')
    args=parser.parse_args()
    root=args.project_root.resolve()
    try:
        files=prepare(root)
        if not files:
            print('Already installed; both source files are present and match this package.')
            return
        print('Prepared source dependency update:')
        for relative in files: print('  '+relative)
        if not args.apply:
            print('Preview only. Add --apply to install. No database or remote commands were run.')
            return
        backup=apply(root,files)
        print('Installed. Backup: '+str(backup))
        print('Runtime files verified. Restart the backend, then regenerate affected drafts.')
    except (ValueError,OSError,SyntaxError) as exc:
        parser.exit(2,'Installation stopped: '+str(exc)+'\n')


if __name__=='__main__': main()
