"""Naming suggestions from pasted source. No source import, execution or LLM."""
from __future__ import annotations

import ast
import re
import unicodedata


def _value(node, env, depth=0):
    if depth > 12 or node is None:
        return None
    if isinstance(node, ast.Constant) and type(node.value) in (str, int, bool):
        return node.value if not isinstance(node.value, str) or len(node.value) <= 4096 else None
    if isinstance(node, ast.Name):
        return env.get(node.id)
    if isinstance(node, (ast.Tuple, ast.List)) and len(node.elts) <= 30:
        return [_value(part, env, depth + 1) for part in node.elts]
    if isinstance(node, ast.Dict) and len(node.keys) <= 30:
        pairs = [(_value(k, env, depth + 1), _value(v, env, depth + 1)) for k, v in zip(node.keys, node.values)]
        return dict(pairs) if all(type(k) in (str, int) for k, _ in pairs) else None
    if isinstance(node, ast.Subscript):
        base, key = _value(node.value, env, depth + 1), _value(node.slice, env, depth + 1)
        try:
            return base[key] if isinstance(base, (dict, list, tuple)) and type(key) in (str, int) else None
        except (TypeError, IndexError, KeyError):
            return None
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = _value(node.left, env, depth + 1), _value(node.right, env, depth + 1)
        if isinstance(left, str) and isinstance(right, str) and len(left) + len(right) <= 4096:
            return left + right
    if isinstance(node, ast.JoinedStr):
        values = []
        for part in node.values:
            if isinstance(part, ast.FormattedValue):
                if part.format_spec or part.conversion not in (-1, 115): return None
                value = _value(part.value, env, depth + 1)
            else: value = _value(part, env, depth + 1)
            if type(value) not in (str, int): return None
            values.append(str(value))
        joined = ''.join(values)
        return joined if len(joined) <= 4096 else None
    return None


def source_connections(source):
    """Extract naming hints, not physical host mappings or authorizations."""
    if not source.strip(): return {'connections': [], 'dag_ids': [], 'parse_error': ''}
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, RecursionError):
        return {'connections': [], 'dag_ids': [], 'parse_error': 'Finish pasting valid Python to detect its connections.'}
    if sum(1 for _ in ast.walk(tree)) > 50000:
        return {'connections': [], 'dag_ids': [], 'parse_error': 'Source is too large for naming suggestions; names remain editable.'}
    aliases = {}
    for node in tree.body:
        if isinstance(node, ast.ImportFrom):
            aliases.update({a.asname or a.name: a.name for a in node.names})
    connections, dags = {}, []
    budget = [0]

    def bind(target, value, env):
        if isinstance(target, ast.Name): env[target.id] = value
        elif isinstance(target, (ast.Tuple, ast.List)):
            for i, member in enumerate(target.elts):
                bind(member, value[i] if isinstance(value, (tuple, list)) and i < len(value) else None, env)
        elif isinstance(target, (ast.Subscript, ast.Attribute)):
            owner = target.value
            while isinstance(owner, (ast.Subscript, ast.Attribute)): owner = owner.value
            if isinstance(owner, ast.Name):
                previous = env.get(owner.id)
                for key in list(env):
                    if key == owner.id or (isinstance(previous, (dict, list)) and env[key] is previous): env[key] = None

    def capture(node, env):
        for call in ast.walk(node):
            if not isinstance(call, ast.Call): continue
            name = call.func.id if isinstance(call.func, ast.Name) else call.func.attr if isinstance(call.func, ast.Attribute) else ''
            name = aliases.get(name, name)
            if isinstance(call.func, ast.Attribute) and call.func.attr in {'append', 'extend', 'update', 'pop', 'clear', 'remove', 'insert'}:
                bind(call.func, None, env)
            pairs = []
            for keyword in call.keywords:
                if keyword.arg in {'ssh_conn_id', 'mysql_conn_id', 'postgres_conn_id', 'database_conn_id', 'conn_id'}:
                    kind = 'SSH' if keyword.arg == 'ssh_conn_id' or name in {'SSHHook', 'SSHOperator'} else 'DATABASE'
                    pairs.append((kind, keyword.value))
                if name == 'DAG' and keyword.arg == 'dag_id':
                    value = _value(keyword.value, env)
                    if isinstance(value, str) and value and value not in dags: dags.append(value)
            if name == 'init_db_proj' and call.args: pairs.append(('DATABASE', call.args[0]))
            if name == 'get_connection' and call.args:
                value = _value(call.args[0], env)
                if isinstance(value, str):
                    kind = 'SSH' if re.match(r'(?i)^(ssh|server)[_.-]', value) else 'DATABASE'
                    pairs.append((kind, call.args[0]))
            for kind, expression in pairs:
                value = _value(expression, env)
                if isinstance(value, str) and re.fullmatch(r'[A-Za-z0-9_.:-]{1,128}', value):
                    key = (kind, value)
                    connections.setdefault(key, {'id': value, 'type': kind, 'source_lines': []})
                    if call.lineno not in connections[key]['source_lines']:
                        connections[key]['source_lines'].append(call.lineno)

    def visit(nodes, env):
        for node in nodes:
            budget[0] += 1
            if budget[0] > 5000: return
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                local = dict(env)
                for arg in [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]: local.pop(arg.arg, None)
                visit(node.body, local)
            elif isinstance(node, (ast.Assign, ast.AnnAssign)):
                if node.value: capture(node.value, env)
                value = _value(node.value, env)
                for target in node.targets if isinstance(node, ast.Assign) else [node.target]: bind(target, value, env)
            elif isinstance(node, ast.AugAssign):
                bind(node.target, None, env)
            elif isinstance(node, ast.If):
                condition = _value(node.test, env)
                if type(condition) is bool:
                    visit(node.body if condition else node.orelse, env)
                else:
                    yes, no = dict(env), dict(env)
                    visit(node.body, yes); visit(node.orelse, no)
                    for key in set(yes) | set(no): env[key] = yes.get(key) if yes.get(key) == no.get(key) else None
            elif isinstance(node, ast.For):
                iterable = _value(node.iter, env)
                if isinstance(iterable, (tuple, list, dict)) and len(iterable) <= 30:
                    for value in iterable:
                        local = dict(env); bind(node.target, value, local); visit(node.body, local)
                else:
                    local = dict(env); bind(node.target, None, local); visit(node.body, local)
                visit(node.orelse, dict(env))
            elif isinstance(node, (ast.With, ast.AsyncWith, ast.Try)):
                if isinstance(node, (ast.With, ast.AsyncWith)):
                    for item in node.items: capture(item.context_expr, env)
                visit(node.body, env); visit(getattr(node, 'orelse', []), env)
                if isinstance(node, ast.Try):
                    for handler in node.handlers: visit(handler.body, dict(env))
            else:
                capture(node, env)
    visit(tree.body, {})
    return {'connections': list(connections.values())[:100], 'dag_ids': dags[:20], 'parse_error': ''}


def _slug(value):
    value = unicodedata.normalize('NFKD', value).encode('ascii', 'ignore').decode()
    return re.sub(r'[^A-Za-z0-9]+', '_', value).strip('_')[:100]


def _unique(base, used, limit):
    used = {str(value).casefold() for value in used}
    for index in range(1, len(used) + 2):
        suffix = '' if index == 1 else '_' + str(index)
        candidate = base[:limit - len(suffix)] + suffix
        if candidate.casefold() not in used: return candidate
    raise ValueError('Could not produce a unique name')


def suggest_names(payload, used_target_ids=(), used_credential_names=()):
    kind = payload.get('target_type')
    if not isinstance(kind, str) or kind not in {'DATABASE', 'SSH'}: raise ValueError('Choose a database or SSH target.')
    source = payload.get('dag_source_code', '')
    if not isinstance(source, str) or len(source) > 200000: raise ValueError('DAG source exceeds the naming input limit.')
    for key in ('source_connection_id', 'hostname', 'database_name', 'dag_id', 'target_id'):
        if not isinstance(payload.get(key, ''), str) or len(payload.get(key, '')) > 255:
            raise ValueError('Invalid naming input: ' + key)
    facts = source_connections(source)
    candidates = [entry for entry in facts['connections'] if entry['type'] == kind]
    chosen = next((c for c in candidates if c['id'] == payload.get('source_connection_id')), None)
    if chosen is None and len(candidates) == 1: chosen = candidates[0]
    result = {**facts, 'connections': candidates, 'requires_connection_choice': len(candidates) > 1 and chosen is None,
              'source_connection_id': chosen['id'] if chosen else '', 'suggestions': None}
    if result['requires_connection_choice']: return result
    origin = chosen['id'] if chosen else (payload.get('database_name') if kind == 'DATABASE' else payload.get('hostname'))
    origin = origin or payload.get('hostname') or payload.get('dag_id') or (facts['dag_ids'][0] if len(facts['dag_ids']) == 1 else '')
    if not origin: return result
    stem = re.sub(r'(?i)^(?:mysql|mariadb|postgresql|postgres|database|db|ssh|server)[_.-]+', '', origin)
    stem = re.sub(r'(?i)[_.-]+(?:ssh|conn|connection)$', '', stem)
    stem = _slug(stem) or ('database' if kind == 'DATABASE' else 'server')
    suffix = '_DB' if kind == 'DATABASE' else '_SSH'
    base = stem.upper()
    if not base.endswith(suffix): base += suffix
    preferred = payload.get('target_id', '').strip()
    target = preferred or _unique(base, used_target_ids, 128)
    label = stem.replace('_', ' ').title() + (' database' if kind == 'DATABASE' else ' server')
    creds = list(used_credential_names)
    names = {}
    for field, role in [('databaseCredentialName', 'database_read_only'), ('verifierCredentialName', 'verifier'), ('executorCredentialName', 'executor')]:
        name = _unique((_slug(target).lower() or 'target') + '_' + role, creds, 150)
        creds.append(name); names[field] = name
    result['suggestions'] = {'targetId': target, 'targetDisplayName': label[:255], **names}
    result['basis'] = 'Source connection ' + chosen['id'] if chosen else 'Entered target details or DAG ID'
    return result


def register_target_name_routes(app, admin_dependency):
    from fastapi import Body, Depends, HTTPException
    from .db import database_cursor

    @app.post('/api/admin/onboarding/target-name-suggestions')
    def target_name_suggestions(payload: dict = Body(...), actor: str = Depends(admin_dependency)):
        allowed = {'dag_source_code', 'target_type', 'source_connection_id', 'hostname', 'database_name', 'dag_id', 'target_id'}
        if set(payload) - allowed:
            raise HTTPException(422, 'Only source and non-secret naming fields are accepted.')
        # Validate before querying the registry. No credential material is read.
        try: preview = suggest_names(payload)
        except ValueError as exc: raise HTTPException(422, str(exc)) from exc
        if preview['suggestions'] is None: return preview
        try:
            with database_cursor() as (_, cursor):
                def column(query, name):
                    cursor.execute(query)
                    return [row[name] if isinstance(row, dict) else row[0] for row in cursor.fetchall()]
                used_targets = column('SELECT target_id FROM registered_targets', 'target_id')
                used_targets += column('SELECT database_target_id FROM registered_database_targets', 'database_target_id')
                used_creds = column('SELECT credential_name FROM encrypted_credentials', 'credential_name')
            return suggest_names(payload, used_targets, used_creds)
        except Exception as exc:
            raise HTTPException(503, 'Naming suggestions are unavailable. Retry or edit the names directly.') from exc
