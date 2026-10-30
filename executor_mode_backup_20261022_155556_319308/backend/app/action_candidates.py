"""Extract reviewable action candidates using bounded Python syntax analysis.

Pasted code is never imported, evaluated or executed. Known command text and
runtime process identities are represented separately throughout tracing.
"""
from __future__ import annotations

import ast
import copy
import hashlib
import json
import math
import re
import shlex
from dataclasses import dataclass, field


@dataclass
class Value:
    value: object = None
    known: bool = False
    text: str = ""
    variables: set = field(default_factory=set)
    kind: str = ""
    data: object = None


def literal(value):
    return Value(value, True, str(value))


def name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return name(node.value) + "." + node.attr
    return ""


def merge_values(*values, text="", kind="", data=None):
    return Value(text=text, variables=set().union(*(v.variables for v in values)), kind=kind, data=data)


def selector(command):
    """Return the pgrep pattern, count flag and source owner when explicit."""
    if '||' in command:
        head,tail=command.rsplit('||',1)
        if tail.strip()=='true' or re.fullmatch(r'''\[\s*["']?\$\?["']?\s+-eq\s+1\s*\]''',tail.strip()):
            command=head.strip()
    try:
        parts = shlex.split(command)
    except ValueError:
        return None
    if not parts or parts[0].rsplit("/", 1)[-1] != "pgrep":
        return None
    count, owner, pattern = False, "", []
    skip = False
    for i, part in enumerate(parts[1:], 1):
        if skip:
            skip = False
            continue
        if part in {"-u", "--euid", "-U", "--uid"} and i + 1 < len(parts):
            owner = parts[i + 1]
            skip = True
        elif part == "--count" or (part.startswith("-") and not part.startswith("--") and "c" in part):
            count = True
        elif not part.startswith("-"):
            pattern.append(part)
    if len(pattern) != 1:
        return None
    path = re.sub(r"\[([^\]\\])\]", r"\1", pattern[0]).replace(r"\.", ".")
    exact_path = path if path.startswith("/") and not re.search(r"[\[\]*?^$|{}<>]", path) else ""
    return {"pattern": pattern[0], "process_path": exact_path, "count": count, "owner": owner}


def _read_only(command):
    try:
        parts = shlex.split(command)
    except ValueError:
        return False
    if not parts:
        return False
    base = parts[0].rsplit("/", 1)[-1]
    if base in {"pgrep", "ps", "free", "uptime", "df", "stat", "hostname", "curl"}:
        return not re.search(r"[;&|\n]", command)
    if base == "systemctl" and len(parts) > 1:
        return parts[1] in {"status", "show", "is-active", "is-enabled"}
    if re.fullmatch(r"python[0-9.]*", base) and "-c" in parts:
        try:
            tree = ast.parse(parts[parts.index("-c") + 1])
            allowed = {"print", "psutil.cpu_percent", "psutil.virtual_memory"}
            return all(name(n.func) in allowed for n in ast.walk(tree) if isinstance(n, ast.Call))
        except (ValueError, IndexError, SyntaxError):
            return False
    return False


class Trace:
    def __init__(self, source, variables):
        self.source = source
        self.tree = ast.parse(source)
        if sum(1 for _ in ast.walk(self.tree)) > 15000:
            raise ValueError("Source is too large for action extraction; paste one monitoring DAG")
        self.variables = {}
        for key, value in variables.items():
            try:
                parsed=json.loads(value)
                if isinstance(parsed,float) and not math.isfinite(parsed): continue
                self.variables[key] = parsed
            except (ValueError, TypeError):
                pass
        self.functions = {n.name: n for n in self.tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
        self.aliases = {}
        for node in self.tree.body:
            if isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    self.aliases[alias.asname or alias.name] = alias.name
        self.events = []
        self.globals = {}
        self.depth = 0
        self.calls = 0
        self.notes = []

    def evaluate(self, node, env, guards, scope):
        if node is None:
            return Value()
        if isinstance(node, ast.Constant):
            return literal(node.value)
        if isinstance(node, ast.Name):
            return env.get(node.id, Value(text=node.id))
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            items = [self.evaluate(n, env, guards, scope) for n in node.elts[:60]]
            return Value(items, True, kind="items", variables=set().union(*(v.variables for v in items)))
        if isinstance(node, ast.Dict):
            items = {k.value: self.evaluate(v, env, guards, scope) for k, v in zip(node.keys, node.values)
                     if isinstance(k, ast.Constant) and isinstance(k.value, (str, int))}
            return Value(items, True, kind="mapping", variables=set().union(*(v.variables for v in items.values())))
        if isinstance(node, ast.JoinedStr):
            parts = [self.evaluate(n.value, env, guards, scope) if isinstance(n, ast.FormattedValue)
                     else self.evaluate(n, env, guards, scope) for n in node.values]
            if all(v.known and isinstance(v.value, (str, int, float)) for v in parts):
                return Value("".join(str(v.value) for v in parts), True,
                             variables=set().union(*(v.variables for v in parts)))
            return merge_values(*parts, text="".join(str(v.value) if v.known else "{" + (v.text or v.kind or "runtime") + "}" for v in parts),
                                kind="template", data=parts)
        if isinstance(node, ast.BinOp):
            left, right = (self.evaluate(n, env, guards, scope) for n in (node.left, node.right))
            if left.known and right.known:
                try:
                    if isinstance(node.op, ast.Add) and isinstance(left.value, (str, int, float)) and isinstance(right.value, type(left.value)):
                        result = left.value + right.value
                        if len(str(result)) <= 20000:
                            return Value(result, True, variables=left.variables | right.variables)
                    if isinstance(node.op, ast.Mod) and isinstance(left.value, str):
                        if right.kind=='items' and not all(v.known and type(v.value) in (str,int,float) for v in right.value):
                            raise ValueError('Unresolved formatting input')
                        arguments = tuple(v.value for v in right.value) if right.kind == "items" else right.value
                        return Value(left.value % arguments, True, variables=left.variables | right.variables)
                except (ValueError, TypeError, KeyError):
                    pass
            template=((str(left.value) if left.known else left.text) + (str(right.value) if right.known else right.text) if isinstance(node.op, ast.Add) else ast.unparse(node))
            if isinstance(node.op,ast.Mod) and left.known and isinstance(left.value,str):
                template=re.sub(r'%[-+0-9.]*[sd]', '{runtime_value}', left.value)
            return merge_values(left, right, text=template, kind="template", data=[left, right])
        if isinstance(node, ast.Subscript):
            base = self.evaluate(node.value, env, guards, scope)
            index = self.evaluate(node.slice, env, guards, scope)
            if base.kind in {"items", "mapping"} and index.known:
                try:
                    return base.value[index.value]
                except (IndexError, KeyError, TypeError):
                    pass
            if base.kind == "ssh_result" and index.known and index.value in (0, 1, 2):
                return Value(kind="stream", data=base.data, variables=base.variables)
            if base.kind in {"stream", "output", "lines"}:
                event = base.data
                info = event.get("selector")
                if info:
                    if info["count"]:
                        return Value(kind="metric", data={"kind": "process_count", "selector": info, "event": event}, variables=base.variables)
                    return Value(kind="pid", data={"selector": info, "event": event, "skip": 0}, variables=base.variables, text="runtime_pid")
                if event.get("memory_metrics") and index.known and index.value in event["memory_metrics"]:
                    return Value(kind="metric", data={"kind": event["memory_metrics"][index.value], "event": event}, variables=base.variables)
            if base.kind == "pid_list":
                data = dict(base.data)
                if isinstance(node.slice, ast.Slice):
                    lower = self.evaluate(node.slice.lower, env, guards, scope)
                    data["skip"] = lower.value if lower.known and type(lower.value) is int and lower.value >= 0 else None
                    return Value(kind="pid_list", data=data, variables=base.variables)
                return Value(kind="pid", data=data, variables=base.variables, text="runtime_pid")
            return merge_values(base, index, text=ast.unparse(node))
        if isinstance(node, (ast.ListComp, ast.GeneratorExp)):
            if node.generators:
                base = self.evaluate(node.generators[0].iter, env, guards, scope)
                if base.kind == "pid_list":
                    return base
            return Value(text=ast.unparse(node))
        if isinstance(node, ast.Call):
            called = name(node.func)
            root = called.split(".")[0]
            called = self.aliases.get(root, root) + called[len(root):]
            short = called.rsplit(".", 1)[-1]
            args = [self.evaluate(n, env, guards, scope) for n in node.args]
            keywords = {kw.arg: self.evaluate(kw.value, env, guards, scope) for kw in node.keywords if kw.arg}
            if called in {"Variable.get", "airflow.models.Variable.get"} and args and args[0].known:
                key = str(args[0].value)
                if key in self.variables:
                    return Value(self.variables[key], True, variables={key})
                return Value(text="Airflow Variable " + key, variables={key}, kind="variable")
            if short in {"str", "int", "float"} and args:
                value = args[0]
                if value.known and value.kind not in {"items", "mapping"}:
                    try:
                        return Value({"str": str, "int": int, "float": float}[short](value.value), True, variables=value.variables)
                    except (TypeError, ValueError):
                        pass
                return value
            if short == "len" and args:
                value = args[0]
                if value.kind == "pid_list":
                    return Value(kind="metric", data={"kind": "process_count", **value.data}, variables=value.variables)
                if value.kind == "items":
                    return literal(len(value.value))
                return Value(kind="output_validity", variables=value.variables)
            if short == "SSHHook":
                conn = keywords.get("ssh_conn_id", args[0] if args else Value())
                return Value(kind="connection", data=[str(conn.value)] if conn.known else [], variables=conn.variables)
            if short == "TriggerDagRunOperator":
                return Value(kind="trigger", data=keywords)
            if short in {"exec_command", "SSHOperator", "BashOperator", "run_ssh_command"}:
                command = keywords.get("command") or keywords.get("bash_command") or (args[0] if args else Value())
                receiver = self.evaluate(node.func.value, env, guards, scope) if isinstance(node.func, ast.Attribute) else Value()
                connection = keywords.get("ssh_conn_id", Value())
                conns = receiver.data if receiver.kind == "connection" else ([connection.value] if connection.known else [])
                if command.kind=='choices':
                    for option in command.data:
                        self.remote(node,option['value'],guards+option['guards'],scope,conns,'SSH target')
                    return Value(kind='ambiguous_stream',variables=command.variables)
                event = self.remote(node, command, guards, scope, conns, "Airflow worker" if short == "BashOperator" else "SSH target")
                return Value(kind="ssh_result", data=event, variables=command.variables)
            if isinstance(node.func, ast.Attribute):
                base = self.evaluate(node.func.value, env, guards, scope)
                if base.kind == "trigger" and short == "execute":
                    event = {"kind": "trigger", "line": node.lineno, "scope": scope, "guards": guards,
                             "dag": base.data.get("trigger_dag_id", Value()), "variables": set()}
                    self.events.append(event)
                    return Value()
                if short == "get_conn" and base.kind == "connection":
                    return base
                if short=='join' and base.known and isinstance(base.value,str) and args:
                    items=args[0]
                    if items.kind=='items' and all(v.known and isinstance(v.value,str) for v in items.value):
                        return Value(base.value.join(v.value for v in items.value),True,variables=items.variables)
                    return merge_values(items,kind='template',text='runtime_pids',data=[items])
                if short in {"read", "readlines", "decode", "strip", "rstrip", "split"}:
                    if base.known and isinstance(base.value, str):
                        try:
                            if short in {"strip", "rstrip"}:
                                return Value(base.value.strip(), True, variables=base.variables)
                            if short == "split":
                                return Value([literal(x) for x in base.value.split()], True, kind="items", variables=base.variables)
                        except ValueError:
                            pass
                    if base.kind in {"stream", "lines", "output"}:
                        event = base.data
                        if short == "split" and event.get("selector") and not event["selector"]["count"]:
                            return Value(kind="pid_list", data={"selector": event["selector"], "event": event, "skip": 0}, variables=base.variables)
                        return Value(kind="lines" if short == "readlines" else "output", data=event, variables=base.variables)
                    return base
                if short == "format" and base.known and isinstance(base.value, str):
                    if all(v.known for v in args) and all(v.known for v in keywords.values()):
                        try:
                            if re.search(r"\{[^{}]*[.\[]", base.value):
                                raise ValueError("Attribute interpolation is not resolved")
                            return Value(base.value.format(*(v.value for v in args), **{k:v.value for k,v in keywords.items()}), True,
                                         variables=base.variables | set().union(*(v.variables for v in args), *(v.variables for v in keywords.values())))
                        except (ValueError, KeyError, IndexError):
                            pass
                    return merge_values(base, *args, *keywords.values(), text=base.value, kind="template", data=args)
            if short in self.functions and self.depth < 5 and self.calls < 100:
                function = self.functions[short]
                child = dict(self.globals)
                for arg, value in zip(function.args.args, args):
                    child[arg.arg] = value
                child.update(keywords)
                self.depth += 1
                self.calls += 1
                result = self.walk(function.body, child, guards, scope + "/" + short)
                self.depth -= 1
                return result or Value()
            return merge_values(*args, *keywords.values(), text=ast.unparse(node))
        if isinstance(node, (ast.Compare, ast.BoolOp, ast.UnaryOp)):
            return Value(kind="predicate", data=self.predicate(node, env, guards, scope))
        return Value(text=ast.unparse(node))

    def remote(self, node, command, guards, scope, conns, location):
        if len(self.events) >= 150:
            raise ValueError("Too many operations in one DAG; extract one component at a time")
        text = str(command.value) if command.known else command.text
        info = selector(text)
        if info is None and command.variables and re.match(r"\s*(?:\S*/)?pgrep\s",text):
            info={"pattern":text,"process_path":"","count":bool(re.search(r"--count\b|-[a-z]*c[a-z]*\b",text)),"owner":""}
        metrics = {}
        interpreter = "python3"
        try:
            parts = shlex.split(text)
            if parts and "-c" in parts and re.fullmatch(r"python[0-9.]*", parts[0].rsplit("/",1)[-1]):
                interpreter = parts[0]
                script = ast.parse(parts[parts.index("-c")+1])
                printed = [stmt.value.args[0] for stmt in script.body if isinstance(stmt, ast.Expr)
                           and isinstance(stmt.value, ast.Call) and name(stmt.value.func) == "print" and stmt.value.args]
                for index, printed_node in enumerate(printed):
                    value = ast.unparse(printed_node)
                    if value == "psutil.virtual_memory().percent":
                        metrics[index] = "memory_percent"
                    elif value.startswith("psutil.cpu_percent("):
                        metrics[index] = "cpu_percent"
        except (ValueError, IndexError, SyntaxError):
            pass
        event = {"kind": "remote", "line": node.lineno, "scope": scope, "command": command,
                 "guards": list(guards), "connections": list(conns or []), "location": location,
                 "selector": info, "memory_metrics": metrics, "interpreter": interpreter}
        self.events.append(event)
        return event

    def predicate(self, node, env, guards, scope):
        if isinstance(node, ast.Compare) and len(node.ops) == 1:
            return {"op": type(node.ops[0]).__name__, "left": self.evaluate(node.left, env, guards, scope),
                    "right": self.evaluate(node.comparators[0], env, guards, scope)}
        if isinstance(node, ast.BoolOp):
            return {"op": type(node.op).__name__, "values": [self.predicate(v, env, guards, scope) for v in node.values]}
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            return {"op": "Not", "value": self.predicate(node.operand, env, guards, scope)}
        return {"op": "Unknown", "text": ast.unparse(node)}

    def bind(self, target, value, env):
        if isinstance(target, ast.Name):
            env[target.id] = value
        elif isinstance(target, (ast.Tuple, ast.List)):
            for i, item in enumerate(target.elts):
                child = Value(kind="stream", data=value.data, variables=value.variables) if value.kind == "ssh_result" else (
                    value.value[i] if value.kind == "items" and i < len(value.value) else Value())
                self.bind(item, child, env)

    def constant_truth(self,predicate):
        op=predicate['op']
        if op in {'And','Or'}:
            values=[self.constant_truth(p) for p in predicate['values']]
            return (all(values) if op=='And' else any(values)) if all(v is not None for v in values) else None
        if op=='Not':
            value=self.constant_truth(predicate['value'])
            return not value if value is not None else None
        if op not in {'Eq','NotEq','Gt','GtE','Lt','LtE'}: return None
        a,b=predicate['left'],predicate['right']
        if not a.known or not b.known or type(a.value) not in (str,int,float,bool) or type(b.value) not in (str,int,float,bool): return None
        try:
            if op=='Eq': return a.value==b.value
            if op=='NotEq': return a.value!=b.value
            if op=='Gt': return a.value>b.value
            if op=='GtE': return a.value>=b.value
            if op=='Lt': return a.value<b.value
            return a.value<=b.value
        except TypeError: return None

    def walk(self, statements, env, guards, scope):
        for statement in statements:
            if isinstance(statement, (ast.Assign, ast.AnnAssign)):
                value = self.evaluate(statement.value, env, guards, scope)
                for target in (statement.targets if isinstance(statement, ast.Assign) else [statement.target]):
                    self.bind(target, value, env)
                if scope == "module":
                    self.globals = dict(env)
            elif isinstance(statement, ast.Expr):
                self.evaluate(statement.value, env, guards, scope)
            elif isinstance(statement, ast.Return):
                return self.evaluate(statement.value, env, guards, scope)
            elif isinstance(statement, ast.If):
                if isinstance(statement.test, (ast.Constant,ast.Name)):
                    test=self.evaluate(statement.test,env,guards,scope)
                else:
                    test=Value()
                if test.known and type(test.value) in (bool,int,str):
                    self.walk(statement.body if test.value else statement.orelse, env, guards, scope)
                    continue
                predicate = self.predicate(statement.test, env, guards, scope)
                truth=self.constant_truth(predicate)
                if truth is not None:
                    self.walk(statement.body if truth else statement.orelse,env,guards,scope)
                    continue
                left, right = dict(env), dict(env)
                self.walk(statement.body, left, guards + [predicate], scope)
                self.walk(statement.orelse, right, guards + [{"op":"Not", "value":predicate}], scope)
                # A branch assignment cannot leak a chosen runtime value into
                # later commands. Preserve only unchanged/equal literals.
                for key in set(left) | set(right):
                    a, b = left.get(key, Value()), right.get(key, Value())
                    if a is b or (a.known and b.known and a.value == b.value):
                        env[key] = a
                    elif a.kind=='metric' and b.known:
                        env[key]=a
                    elif b.kind=='metric' and a.known:
                        env[key]=b
                    elif a.known and b.known and isinstance(a.value,str) and isinstance(b.value,str):
                        env[key]=merge_values(a,b,kind='choices',data=[{'value':a,'guards':[predicate]},{'value':b,'guards':[{'op':'Not','value':predicate}]}])
                    else:
                        env[key] = merge_values(a,b,text=key)
            elif isinstance(statement, (ast.For, ast.AsyncFor)):
                value = self.evaluate(statement.iter, env, guards, scope)
                if value.kind == "items":
                    items = value.value[:40]
                elif value.kind == "pid_list":
                    items = [Value(kind="pid",data={**value.data,'many':True},variables=value.variables,text="runtime_pid")]
                else:
                    items = [Value(text="runtime_loop_value")]
                for item in items:
                    child = dict(env)
                    self.bind(statement.target,item,child)
                    self.walk(statement.body,child,guards,scope)
            elif isinstance(statement, ast.Try):
                self.walk(statement.body,env,guards,scope)
                for handler in statement.handlers:
                    self.walk(handler.body,dict(env),guards + [{"op":"Unknown","text":"exception handler"}],scope)
                self.walk(statement.orelse,env,guards,scope)
                self.walk(statement.finalbody,dict(env),guards,scope)
            elif isinstance(statement, (ast.With, ast.AsyncWith)):
                self.walk(statement.body,env,guards,scope)
        return None

    def run(self):
        self.walk(self.tree.body, {}, [], "module")
        if not self.events:
            for function in self.functions.values():
                if any(name(d).endswith("task") or (isinstance(d, ast.Call) and name(d.func).endswith("task")) for d in function.decorator_list):
                    self.walk(function.body,dict(self.globals),[],"task/"+function.name)
            if self.events:
                self.notes.append("Task definitions were inspected; their DAG call sites were not present in this paste.")
        return self.events


def _values(predicate):
    if predicate.get("op") in {"And", "Or"}:
        return [v for child in predicate["values"] for v in _values(child)]
    if predicate.get("op") == "Not":
        return _values(predicate["value"])
    return [v for key in ("left","right") if isinstance((v:=predicate.get(key)), Value)]


def _predicate_text(predicate):
    op = predicate["op"]
    if op in {"And", "Or"}:
        return (" and " if op=="And" else " or ").join(_predicate_text(x) for x in predicate["values"])
    if op == "Not":
        child=predicate['value']
        inverse={'Eq':'NotEq','NotEq':'Eq','Gt':'LtE','GtE':'Lt','Lt':'GtE','LtE':'Gt'}
        if child.get('op') in inverse:
            return _predicate_text({**child,'op':inverse[child['op']]})
        return "not (" + _predicate_text(predicate["value"]) + ")"
    if op in {'Eq','NotEq','Gt','GtE','Lt','LtE'}:
        left,right=predicate['left'],predicate['right']
        if left.kind=='metric' and right.known and type(right.value) in (int,float):
            metric=left.data['kind']
            number=right.value
            if metric=='process_count' and op=='Eq' and number in (0,1):
                discovered=not left.data.get('selector',{}).get('count',True)
                if discovered:
                    return 'PID discovery confirms '+('no matches' if number==0 else 'exactly one match')
                return 'No matching process is running' if number==0 else 'Exactly one matching process is running'
            if metric in {'memory_percent','cpu_percent'}:
                comparison={'Eq':'equal to','NotEq':'different from','Gt':'above','GtE':'at least','Lt':'below','LtE':'at most'}[op]
                label='Server RAM usage' if metric=='memory_percent' else 'Server CPU usage'
                return label+' is '+comparison+' '+str(number)+'%'
    def readable(v):
        if v.kind == "metric":
            return {"process_count":"process count","memory_percent":"RAM usage (%)","cpu_percent":"CPU usage (%)"}.get(v.data["kind"],v.data["kind"])
        return str(v.value) if v.known else v.text or v.kind or "unresolved value"
    operators={"Eq":"=","NotEq":"≠","Gt":">","GtE":"≥","Lt":"<","LtE":"≤"}
    return readable(predicate["left"]) + " " + operators[op] + " " + readable(predicate["right"]) if op in operators else predicate.get("text","unresolved condition")


def _compile_predicate(predicate):
    op = predicate["op"]
    if op in {"And","Or"}:
        values=[_compile_predicate(x) for x in predicate["values"]]
        return {"op":op,"values":values} if all(x is not None for x in values) else None
    if op=="Not":
        value=_compile_predicate(predicate["value"])
        return {"op":"Not","value":value} if value else None
    if op not in {"Eq","NotEq","Gt","GtE","Lt","LtE"}:
        return None
    def operand(v):
        if v.kind=="metric" and v.data["kind"] in {"process_count","memory_percent","cpu_percent"}:
            return {"metric":v.data["kind"]}
        if v.known and type(v.value) in (int,float,str,bool) and not (isinstance(v.value,float) and not math.isfinite(v.value)):
            return {"literal":v.value}
        return None
    left,right=operand(predicate["left"]),operand(predicate["right"])
    return {"op":op,"left":left,"right":right} if left is not None and right is not None else None


def _health_command(path, owner, interpreter, predicates, operation, expected_count):
    """Generate a read-only current-state predicate from traced measurements."""
    config={"path":path,"owner":owner,"predicates":predicates,"operation":operation,"expected":expected_count}
    program='''# RCA_SOURCE_HEALTH_V1
import json, pathlib, pwd, sys
c=json.loads(sys.argv[1])
measurements={"process_count":0}
try:
    for p in pathlib.Path('/proc').iterdir():
        if not p.name.isdigit() or int(p.name)<=1: continue
        try:
            argv=[x.decode('utf-8','surrogateescape') for x in (p/'cmdline').read_bytes().split(b'\\0') if x]
            if c['path'] not in argv: continue
            if c['owner'] and pwd.getpwuid(p.stat().st_uid).pw_name!=c['owner']: continue
            stat=(p/'stat').read_text()
            if stat[stat.rfind(')')+2:].split()[0]!='Z': measurements['process_count']+=1
        except (FileNotFoundError,ProcessLookupError): continue
    needed=json.dumps(c['predicates'])
    if 'memory_percent' in needed or 'cpu_percent' in needed:
        import psutil
        if 'memory_percent' in needed: measurements['memory_percent']=psutil.virtual_memory().percent
        if 'cpu_percent' in needed: measurements['cpu_percent']=psutil.cpu_percent(interval=1)
    def evaluate(p):
        op=p['op']
        if op=='And': return all(evaluate(x) for x in p['values'])
        if op=='Or': return any(evaluate(x) for x in p['values'])
        if op=='Not': return not evaluate(p['value'])
        def operand(v): return measurements[v['metric']] if 'metric' in v else v['literal']
        a,b=operand(p['left']),operand(p['right'])
        if op=='Eq': return a==b
        if op=='NotEq': return a!=b
        if op=='Gt': return a>b
        if op=='GtE': return a>=b
        if op=='Lt': return a<b
        if op=='LtE': return a<=b
        raise ValueError('Unsupported predicate')
    count=measurements['process_count']
    if c['operation']=='STOP_PROCESSES' and count==0: state='HEALTHY'
    elif all(evaluate(p) for p in c['predicates']): state='ACTION_REQUIRED'
    elif count==c['expected']: state='HEALTHY'
    else: state='INCONCLUSIVE'
    print(state)
except Exception as exc:
    print(str(exc),file=sys.stderr)
    raise SystemExit(2)
'''
    return shlex.quote(interpreter)+" -c "+shlex.quote(program)+" "+shlex.quote(json.dumps(config,separators=(",",":")))


def extract_action_candidates(source, variable_values=None, component_id="", related_dag_sources=None):
    if not source.strip():
        return {"candidates":[],"required_variables":[],"notes":["Paste the DAG to detect actions."]}
    try:
        trace=Trace(source,variable_values or {})
        events=trace.run()
    except SyntaxError as exc:
        raise ValueError('Invalid Python near source line '+str(exc.lineno)+': '+str(exc.msg)) from exc
    except RecursionError as exc:
        raise ValueError('Source nesting is too deep; paste one DAG component') from exc
    digest=hashlib.sha256(source.encode()).hexdigest()
    if not component_id:
        ids={kw.value.value for node in ast.walk(trace.tree) if isinstance(node,ast.Call)
             for kw in node.keywords if kw.arg=="dag_id" and isinstance(kw.value,ast.Constant) and isinstance(kw.value.value,str)}
        component_id=next(iter(ids)) if len(ids)==1 else "component"
    candidates=[]
    required=set()
    consumed=set()
    for index,event in enumerate(events):
        if event["kind"]!="remote" or id(event) in consumed: continue
        value=event["command"]
        text=str(value.value) if value.known else value.text
        if _read_only(text): continue
        if not re.search(r"\b(?:kill|pkill|killall|restart|start|stop|reboot|shutdown|taskkill)\b|(?:python[0-9.]*\s+[^\n]+\.py)|\.sh\b",text,re.I) and not (value.variables and not value.known):
            continue
        prefill={"action_id":re.sub(r"[^a-z0-9_-]","_",component_id.lower())[:90]+"_action_"+str(event["line"]),
                 "display_name":"Review detected action", "operation":"CUSTOM_COMMAND", "command":text if value.known else ""}
        missing=[]
        notes=[]
        followup=None
        process_pattern=''
        if value.variables and not value.known:
            notes.append('A deployed variable contributes to this operation. Its value is needed to resolve the command; no command text is invented.')
        variables=set(value.variables)
        for condition in event['guards']:
            for operand in _values(condition): variables.update(operand.variables)
        runtime_pids=[]
        def pid_parts(v):
            if v.kind in {"pid","pid_list"}: runtime_pids.append(v)
            if v.kind=="template" and isinstance(v.data,list):
                for part in v.data: pid_parts(part)
            if v.kind=='items':
                for part in v.value: pid_parts(part)
        pid_parts(value)
        follow=[]
        root_scope=event['scope'].split('/')[:2]
        for later in events[index+1:index+12]:
            if later['scope'].split('/')[:2]!=root_scope: continue
            compatible=len(later['guards'])>=len(event['guards']) and later['guards'][:len(event['guards'])]==event['guards']
            if later['kind']=='trigger':
                if compatible: follow.append(later)
                break
            if later['kind']=='remote':
                cmd=later['command']
                following=str(cmd.value) if cmd.known else cmd.text
                if not _read_only(following) and re.search(r"\b(?:start|restart)\b|\.sh\b|python[0-9.]*\s+.*\.py",following,re.I):
                    if compatible: follow.append(later)
                    break
        # A dynamic PID never becomes a saved literal kill command.
        if runtime_pids and re.match(r"\s*(?:sudo\s+)?kill\b",text):
            pid=runtime_pids[0]
            info=pid.data['selector']
            process_pattern=info.get('pattern','')
            path=info.get('process_path','')
            operation="TRIM_PROCESSES" if pid.data.get('skip',0) else ("RESTART_SCRIPT" if follow else "STOP_PROCESSES")
            prefill.update(operation=operation,process_path=path,owner=info.get('owner',''),command="",
                           expected_count=pid.data.get('skip') or 1,max_matches=20 if operation=='TRIM_PROCESSES' or pid.kind=='pid_list' or pid.data.get('many') else 1,
                           display_name={"TRIM_PROCESSES":"Remove excess script processes","RESTART_SCRIPT":"Restart monitored script","STOP_PROCESSES":"Stop monitored script"}[operation])
            if re.search(r'(?:\s-9\b|\s-KILL\b|\s-s\s+KILL\b|SIGKILL)',text): prefill['signal']='KILL'
            if not path: missing.append('process_path')
            if follow:
                following=follow[0]
                if following['kind']=='remote' and following['command'].known:
                    prefill['command']=str(following['command'].value)
                    consumed.add(id(following))
                elif following['kind']=='trigger':
                    dag=following['dag']
                    followup={'dag_id':str(dag.value) if dag.known else dag.text,'source_line':following['line'],'resolved':dag.known}
                    notes.append("The source then triggers Airflow DAG '"+followup['dag_id']+"'. Paste that DAG below to fill its startup command, or enter the command directly.")
                    variables.update(dag.variables)
                if not prefill['command']: missing.append('command')
            compiled=[]
            unsupported=False
            for condition in event['guards']:
                for operand in _values(condition): variables.update(operand.variables)
                result=_compile_predicate(condition)
                values=_values(condition)
                cross_scope=any(v.kind=='metric' and v.data.get('kind')=='process_count'
                    and v.data.get('selector',{}).get('process_path') and path
                    and v.data['selector']['process_path']!=path for v in values)
                if result and not cross_scope: compiled.append(result)
                elif not any(v.kind=='output_validity' for v in values): unsupported=True
            metric_events=[operand.data.get('event') for condition in event['guards'] for operand in _values(condition) if operand.kind=='metric']
            memory=next((e for e in metric_events if e and e.get('memory_metrics')),None)
            if memory: prefill['python_executable']=memory['interpreter']
            if compiled or unsupported:
                prefill['source_health_policy']={'predicates':compiled,'unresolved':unsupported}
            if path and compiled and not unsupported:
                prefill.update(health_command=_health_command(path,prefill.get('owner',''),prefill.get('python_executable','python3'),compiled,operation,prefill['expected_count']),
                               healthy_stdout_regex="HEALTHY",unhealthy_stdout_regex="ACTION_REQUIRED")
            elif unsupported:
                missing.append('health_command')
                notes.append("Some source conditions could not be translated. Review the health check before generating the SOP.")
            notes.append("Runtime PIDs are discovered again by the process action; no source PID is copied into the catalog.")
        else:
            if not value.known: missing.append('command')
            try:
                parts=shlex.split(text)
            except ValueError: parts=[]
            if len(parts)>=3 and parts[0].rsplit('/',1)[-1]=='systemctl' and parts[1] in {'restart','start','stop','try-restart','reload-or-restart'}:
                units=[p for p in parts[2:] if not p.startswith('-')]
                if len(units)==1:
                    unit=shlex.quote(units[0])
                    prefill.update(display_name=parts[1].capitalize()+" "+units[0],
                        health_command="state=$(systemctl is-active -- "+unit+"); code=$?; if [ \"$code\" -eq 0 ] || [ \"$code\" -eq 3 ] || [ \"$code\" -eq 4 ]; then printf '%s\\n' \"$state\"; else exit 2; fi",
                        healthy_stdout_regex="inactive|failed|unknown" if parts[1]=='stop' else "active",
                        unhealthy_stdout_regex="active" if parts[1]=='stop' else "inactive|failed|unknown")
                    notes.append("A service status check was derived from the service command; review it with the action.")
                    if event['guards']:
                        notes.append('The service status check does not reproduce the source eligibility conditions listed above. Review or replace it for the action you intend to approve.')
            if not prefill.get('health_command') and value.known and event['guards']:
                compiled=[_compile_predicate(p) for p in event['guards']]
                process_metrics=[operand.data for p in event['guards'] for operand in _values(p)
                                 if operand.kind=='metric' and operand.data.get('kind')=='process_count']
                paths={metric['selector'].get('process_path') for metric in process_metrics if metric.get('selector')}
                paths.discard('')
                if len(paths)==1 and all(p is not None for p in compiled):
                    path=next(iter(paths))
                    prefill.update(health_command=_health_command(path,'','python3',compiled,'CUSTOM_COMMAND',1),
                                   healthy_stdout_regex='HEALTHY',unhealthy_stdout_regex='ACTION_REQUIRED')
                    notes.append('A current-state health check was derived from the source process condition; review it with the command.')
            if not prefill.get('health_command'): missing.append('health_command')
        for variable in variables:
            if variable not in trace.variables: required.add(variable)
        if variables - trace.variables.keys():
            notes.append("Supply the missing deployed values below to resolve this candidate.")
        conditions=[_predicate_text(p) for p in event['guards']]
        binding=json.dumps([event['line'],event['scope'],text,prefill.get('process_path'),conditions],ensure_ascii=False)
        candidate_id="action_"+hashlib.sha256((digest+binding).encode()).hexdigest()[:16]
        candidates.append({"id":candidate_id,"source_line":event['line'],"source_expression":text,
            "source_connections":event['connections'],"execution_location":event['location'],
            "conditions":conditions,"prefill":prefill,
            "followup":followup,"process_pattern":process_pattern,
            "missing_fields":sorted(set(missing)),"required_variables":sorted(variables-trace.variables.keys()),
            "notes":notes})
    dependencies=[{"source_line":e['line'],"dag_id":str(e['dag'].value) if e['dag'].known else e['dag'].text}
                  for e in events if e['kind']=='trigger']
    result={"source_sha256":digest,"candidates":candidates,"triggered_dags":dependencies,
            "required_variables":[{"key":key,"prompt":"Deployed value of Airflow Variable '"+key+"'"} for key in sorted(required)],
            "notes":trace.notes+([] if candidates else ["No supported SSH repair command was resolved. You can still define a reviewed action manually."])}
    if related_dag_sources:
        _link_startup_sources(result,related_dag_sources,variable_values or {})
    return result


def _startup_shape(command):
    """Recognize launch operations without executing or rewriting their text."""
    try:
        parts=shlex.split(command)
    except ValueError:
        return None
    # Shell assignments and common launch wrappers do not provide a new target.
    while parts and (re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*=.*',parts[0]) or parts[0] in {'nohup','exec','env'}):
        parts=parts[1:]
    if parts and parts[0]=='sudo':
        parts=parts[1:]
        while parts and parts[0].startswith('-'):
            flag=parts.pop(0)
            if flag in {'-u','-g','--user','--group'} and parts: parts.pop(0)
    if not parts: return None
    base=parts[0].rsplit('/',1)[-1]
    if base in {'systemctl','supervisorctl'} and len(parts)>1 and parts[1] in {'start','restart','try-restart','reload-or-restart'}:
        return {'script_path':''}
    if base=='service' and len(parts)>2 and parts[2] in {'start','restart'}:
        return {'script_path':''}
    if re.fullmatch(r'(?:python[0-9.]*|pypy[0-9.]*)',base):
        # -c and -m launch semantics cannot identify an exact script argument.
        if '-c' in parts or '-m' in parts: return None
        scripts=[p for p in parts[1:] if p.endswith('.py') and not p.startswith('-')]
        return {'script_path':scripts[0] if len(scripts)==1 and scripts[0].startswith('/') else '',
                'foreground_script':not command.rstrip().endswith('&')}
    if base in {'bash','sh','dash','ksh'}:
        if '-c' in parts: return None
        scripts=[p for p in parts[1:] if p.endswith('.sh')]
        return {'script_path':''} if scripts else None
    if base.endswith('.sh') or (base=='java' and '-jar' in parts):
        return {'script_path':''}
    return None


def _source_dag_ids(source, variables):
    trace=Trace(source,variables)
    trace.run()
    result=set()
    for node in ast.walk(trace.tree):
        if not isinstance(node,ast.Call) or name(node.func).rsplit('.',1)[-1]!='DAG': continue
        for keyword in node.keywords:
            if keyword.arg=='dag_id':
                value=trace.evaluate(keyword.value,trace.globals,[], 'identity')
                if value.known and isinstance(value.value,str): result.add(value.value)
    return result


def _startup_fields(candidate, option):
    fields={'command':option['command']}
    path=option.get('script_path','')
    pattern=re.sub(r'\[([^\]\\])\]',r'\1',candidate.get('process_pattern','')).replace(r'\.', '.')
    if (not candidate['prefill'].get('process_path') and path and pattern and
            not re.search(r'[\[\]*?^$|{}<>]',pattern) and path.rsplit('/',1)[-1]==pattern):
        fields['process_path']=path
    return fields


def _apply_startup(candidate, option):
    fields=_startup_fields(candidate,option)
    candidate['prefill'].update(fields)
    candidate['missing_fields']=[v for v in candidate['missing_fields'] if v not in fields]
    candidate['startup_source']={key:option[key] for key in ('id','dag_id','source_line','source_connections')}
    candidate['notes']=[n for n in candidate['notes'] if not n.startswith('The source then triggers Airflow DAG')]
    candidate['notes'].append("Startup command filled from DAG '"+option['dag_id']+"', source line "+str(option['source_line'])+". Review the command and selected server before activation.")
    if 'process_path' in fields:
        candidate['notes'].append('The full process path comes from the startup command and matches the monitored filename.')


def _link_startup_sources(result, sources, variables):
    """Link only source explicitly supplied for a declared DAG dependency."""
    result['related_source_results']={}
    requested={item['dag_id'] for item in result['triggered_dags']}
    required={v['key'] for v in result['required_variables']}
    for dag_id,source in sources.items():
        if dag_id not in requested or not source.strip(): continue
        review={'dag_id':dag_id,'source_sha256':hashlib.sha256(source.encode()).hexdigest(),'options':[],'notes':[],'error':''}
        result['related_source_results'][dag_id]=review
        try:
            ids=_source_dag_ids(source,variables)
            if ids and dag_id not in ids:
                review['error']="This source declares "+', '.join(sorted(ids))+"; paste the source for '"+dag_id+"'."
                continue
            if len(ids)>1:
                review['error']="Paste just the source for '"+dag_id+"'; this paste declares several DAGs."
                continue
            extracted=extract_action_candidates(source,variables,dag_id)
        except ValueError as exc:
            review['error']=str(exc)
            continue
        except SyntaxError as exc:
            review['error']='Invalid Python near source line '+str(exc.lineno)+': '+str(exc.msg)
            continue
        except RecursionError:
            review['error']='Source nesting is too deep; paste one restart DAG.'
            continue
        if not ids:
            review['notes'].append('A DAG identity could not be resolved in this snippet; confirm it belongs to '+dag_id+'.')
        for item in extracted['candidates']:
            prefill=item['prefill']
            command=prefill.get('command','')
            shape=_startup_shape(command or item['source_expression'])
            if shape is None and not (not command and item['required_variables']): continue
            option={'id':item['id'],'dag_id':dag_id,'source_line':item['source_line'],
                    'command':command,'source_expression':item['source_expression'],
                    'source_connections':item['source_connections'],'execution_location':item['execution_location'],
                    'conditions':item['conditions'],'required_variables':item['required_variables'],
                    'script_path':shape['script_path'] if shape else '', 'notes':[]}
            if item['conditions']:
                option['notes'].append('This command has source conditions; review them before using it as the startup command.')
            if item['execution_location']!='SSH target':
                option['notes'].append('The source runs this on an Airflow worker. Use it only if it is also correct on the selected SSH server.')
            if shape and shape.get('foreground_script'):
                option['notes'].append('This launches the script in the foreground. If it is long-running, use a background or service launcher that returns after starting it.')
            review['options'].append(option)
            required.update(item['required_variables'])
        if not review['options']:
            review['notes'].append('No supported startup command was found. You can paste another source snippet or enter the exact command below.')
        linked=[c for c in result['candidates'] if c.get('followup',{} ) and c['followup']['dag_id']==dag_id]
        for candidate in linked:
            options=copy.deepcopy(review['options'])
            candidate['startup_options']=options
            for option in options:
                option['prefill']=_startup_fields(candidate,option)
                conns=set(candidate['source_connections'])
                other=set(option['source_connections'])
                connection_conflict=bool(conns and other and conns.isdisjoint(other))
                path=candidate['prefill'].get('process_path','')
                path_conflict=bool(path and option['script_path'] and path!=option['script_path'])
                if connection_conflict:
                    option['notes'].append('This uses a different Airflow connection. Confirm the selected server before choosing it.')
                if path_conflict:
                    option['notes'].append('Its script path differs from the monitored process. Review the process path and command together.')
                option['automatic']=bool(option['command'] and option['execution_location']=='SSH target' and
                    not option['conditions'] and not connection_conflict and not path_conflict)
            if len(options)==1 and options[0]['automatic']:
                _apply_startup(candidate,options[0])
    result['required_variables']=[{'key':key,'prompt':"Deployed value of Airflow Variable '"+key+"'"} for key in sorted(required)]
