"""Bounded, declarative data flow for source-derived investigation checks.

No pasted Python is imported or executed. This module records a small expression
language, normalizes supported SELECT value expressions, and renders/evaluates
that language without eval/exec. Existing SSH and simple SQL plans are retained.
"""
from __future__ import annotations

import ast
import copy
import datetime as dt
import json
import math
import operator
import re
import string
from functools import lru_cache


def sql_state(text,stop):
    quote=''
    depth=0
    index=0
    while index<stop:
        char=text[index]
        if quote:
            if char=='\\' and quote!='`': index+=2;continue
            if char==quote:
                if index+1<stop and text[index+1]==quote: index+=2;continue
                quote=''
        elif char in "'\"`": quote=char
        elif text.startswith(('--','/*','#'),index): return None
        elif char=='(': depth+=1
        elif char==')': depth-=1
        index+=1
    return quote,depth


def literal(value):
    return {'op':'literal','value':value}


def refs(expression, operation='rows'):
    if isinstance(expression,list): return set().union(*(refs(v,operation) for v in expression))
    if not isinstance(expression,dict): return set()
    result={expression['check']} if expression.get('op')==operation and operation=='rows' else set()
    for value in expression.values():
        if isinstance(value,dict): result.update(refs(value,operation))
        elif isinstance(value,list):
            for item in value: result.update(refs(item,operation))
    return result


def calc_refs(expression):
    if isinstance(expression,list): return set().union(*(calc_refs(v) for v in expression))
    if not isinstance(expression,dict): return set()
    found={expression['id']} if expression.get('op')=='calc' else set()
    for value in expression.values():
        if isinstance(value,dict): found.update(calc_refs(value))
        elif isinstance(value,list):
            for part in value: found.update(calc_refs(part))
    return found


class InvalidMeasurement(ValueError):
    pass


class Evaluation:
    """Evaluate only the declared data language against supplied sample rows."""
    def __init__(self, flow, rows=None, checked_date=None):
        self.calculations={v['id']:v['expression'] for v in flow.get('calculations',[])}
        self.checks={v['id']:v for v in flow.get('checks',[])}
        self.rows=rows or {}
        self.checked_date=checked_date
        self.steps=0
        self.stack=set()
        self.cache={}

    def run(self, node, bindings=None):
        self.steps+=1
        if self.steps>100000: raise InvalidMeasurement('Calculation exceeds the sample evaluation limit')
        bindings=bindings or {}
        if not isinstance(node,dict): raise InvalidMeasurement('Unsupported source expression')
        op=node.get('op')
        def value(part): return self.run(part,bindings)
        if op=='literal': return node['value']
        if op=='item':
            if node['id'] not in bindings: raise InvalidMeasurement('An iteration value is unavailable')
            return bindings[node['id']]
        if op=='calc':
            key=node['id']
            if key in self.cache: return self.cache[key]
            if key in self.stack or key not in self.calculations: raise InvalidMeasurement('Unresolved or cyclic calculation')
            self.stack.add(key)
            try:
                result=value(self.calculations[key])
                self.cache[key]=result
                return result
            finally: self.stack.remove(key)
        if op=='rows':
            key=node['check']
            if key not in self.rows: raise InvalidMeasurement('Missing rows for '+key)
            data=self.rows[key]
            if isinstance(data,dict):
                if data.get('status')!='SUCCESS' or data.get('rows_truncated'): raise InvalidMeasurement('Incomplete result for '+key)
                data=data.get('rows')
            if not isinstance(data,list): raise InvalidMeasurement('Invalid query result for '+key)
            data=[list(row.values()) if isinstance(row,dict) else list(row) for row in data]
            limit=self.checks.get(key,{}).get('result_limit')
            if limit is not None:
                count=value(limit)
                if type(count) is not int or count<0: raise InvalidMeasurement('Invalid dependent row limit')
                data=data[:count]
            return data
        if op in {'list','tuple'}: return [value(v) for v in node['values']]
        if op=='dict': return {value(k):value(v) for k,v in node['entries']}
        if op=='first':
            data=value(node['value'])
            if not data: raise InvalidMeasurement('Expected one result row')
            return data[0]
        if op=='index': return value(node['value'])[value(node['index'])]
        if op=='slice': return value(node['value'])[slice(*(value(node[k]) if node.get(k) else None for k in ('start','stop','step')))]
        if op=='get': return value(node['value']).get(value(node['key']),value(node['default']))
        if op=='if': return value(node['yes'] if value(node['test']) else node['no'])
        if op=='and': return all(value(v) for v in node['values'])
        if op=='or': return any(value(v) for v in node['values'])
        if op=='not': return not value(node['value'])
        if op=='neg': return -value(node['value'])
        if op=='compare':
            values=[value(v) for v in node['values']]
            if any(isinstance(v,float) and not math.isfinite(v) for v in values): raise InvalidMeasurement('Nonfinite measurement')
            operators={'Eq':operator.eq,'NotEq':operator.ne,'Lt':operator.lt,'LtE':operator.le,'Gt':operator.gt,'GtE':operator.ge,
                       'Is':operator.is_,'IsNot':operator.is_not,'In':lambda a,b:a in b,'NotIn':lambda a,b:a not in b}
            return all(operators[k](a,b) for a,k,b in zip(values,node['operators'],values[1:]))
        if op=='binary':
            left,right=value(node['left']),value(node['right'])
            if node['operator']=='Mult' and isinstance(left,(str,list,tuple)) and type(right) is int and len(left)*max(0,right)>100000:
                raise InvalidMeasurement('Source expansion is too large')
            if node['operator']=='Mult' and isinstance(right,(str,list,tuple)) and type(left) is int and len(right)*max(0,left)>100000:
                raise InvalidMeasurement('Source expansion is too large')
            if any(type(v) is int and v.bit_length()>8192 for v in (left,right)): raise InvalidMeasurement('Integer expansion is too large')
            operations={'Add':operator.add,'Sub':operator.sub,'Mult':operator.mul,'Div':operator.truediv,'FloorDiv':operator.floordiv,'Mod':operator.mod}
            result=operations[node['operator']](left,right)
            if isinstance(result,(str,list,tuple)) and len(result)>100000: raise InvalidMeasurement('Source expansion is too large')
            if isinstance(result,float) and not math.isfinite(result): raise InvalidMeasurement('Nonfinite numeric result')
            return result
        if op=='call':
            functions={'len':len,'sum':sum,'min':min,'max':max,'abs':abs,'int':int,'float':float,'str':str,'bool':bool,'round':round,'list':list,'tuple':tuple}
            return functions[node['function']](*(value(v) for v in node['args']))
        if op=='today':
            if self.checked_date is None: raise InvalidMeasurement('The diagnostic calendar date is unavailable')
            return dt.date.fromisoformat(str(self.checked_date)[:10])
        if op=='now':
            if self.checked_date is None or len(str(self.checked_date))<=10: raise InvalidMeasurement('The diagnostic timestamp is unavailable')
            return dt.datetime.fromisoformat(str(self.checked_date))
        if op=='duration': return dt.timedelta(days=value(node['days']))
        if op in {'listcomp','dictcomp'}:
            result=[] if op=='listcomp' else {}
            def expand(index,local):
                if index==len(node['clauses']):
                    if op=='listcomp': result.append(self.run(node['value'],local))
                    else: result[self.run(node['key'],local)]=self.run(node['value'],local)
                    return
                clause=node['clauses'][index]
                data=self.run(clause['source'],local)
                if len(data)>10000: raise InvalidMeasurement('Too many source rows')
                for item in data:
                    child={**local,clause['binding']:item}
                    if all(self.run(test,child) for test in clause['where']): expand(index+1,child)
            expand(0,bindings)
            return result
        if op=='collect':
            result=list(value(node['initial']))
            for item in value(node['source']):
                local={**bindings,node['binding']:item}
                for entry in node['entries']:
                    if all(self.run(test,local) for test in entry['where']):
                        part=self.run(entry['value'],local)
                        if entry['extend']: result.extend(part)
                        else: result.append(part)
            return result
        raise InvalidMeasurement('Unsupported operation '+str(op))


def evaluate_plan(plan, rows, checked_date=None):
    """Sample evaluation, never a database or remote execution entry point."""
    flow=plan.get('dataflow',{})
    evaluator=Evaluation(flow,rows,checked_date)
    results=[]
    errors=[]
    for rule in flow.get('rules',[]):
        try:
            result=evaluator.run(rule['expression'])
            results.append({'rule_id':rule['id'],'matched':bool(result),'outcome':rule['outcome']})
        except (InvalidMeasurement,TypeError,ValueError,KeyError,IndexError,ZeroDivisionError,OverflowError,RecursionError) as exc:
            errors.append(str(exc))
    if any(r['matched'] and r['outcome']=='MANUAL_REVIEW_REQUIRED' for r in results): classification='MANUAL_REVIEW_REQUIRED'
    elif not errors and flow.get('complete') and results and any(r['matched'] and r['outcome']=='SOURCE_NO_ALERT' for r in results): classification='NO_REMEDIATION_REQUIRED'
    else: classification='INCONCLUSIVE'
    if plan.get('coverage_review',{}).get('accepted'): classification='INCONCLUSIVE'
    return {'classification':classification,'rules':results,'error':'; '.join(dict.fromkeys(errors))}


@lru_cache(maxsize=8)
def builder_class(base):
    class DependencyBuilder(base):
        def __init__(self,*args,**kwargs):
            super().__init__(*args,**kwargs)
            self.flow_calculations=[]
            self.flow_rules=[]
            self.flow_checks={}
            self.flow_loops=[]
            self.flow_branches=[]
            self.flow_normalizations=[]
            self.flow_active=False
            self.flow_counter=0
            self.pure_depth=0

        def merged(self,text,values):
            result=super().merged(text,values)
            expressions=[getattr(v,'runtime',None) for v in values]
            if expressions and all(e is not None and e==expressions[0] for e in expressions): result.runtime=copy.deepcopy(expressions[0])
            elif re.fullmatch(r'[A-Za-z_][A-Za-z_0-9]*',text or '') and self.flow_branches and len(expressions)==2 and all(e is not None for e in expressions):
                result.runtime={'op':'if','test':self.flow_branches[-1],'yes':expressions[0],'no':expressions[1]}
            return result

        def expand(self,node,seen=None,budget=None):
            budget=[0] if budget is None else budget
            budget[0]+=1
            if budget[0]>20000: return None
            if isinstance(node,list): return [self.expand(v,seen,budget) for v in node]
            if not isinstance(node,dict): return node
            seen=set() if seen is None else seen
            if len(seen)>80: return None
            if node.get('op')=='calc':
                key=node['id']
                if key in seen: return None
                found=next((v['expression'] for v in self.flow_calculations if v['id']==key),None)
                return self.expand(found,seen|{key},budget)
            return {key:self.expand(value,seen,budget) if isinstance(value,(dict,list)) else value
                    for key,value in node.items()}

        def record(self,name,value,node):
            runtime=getattr(value,'runtime',None)
            if runtime is None or self.flow_loops: return value
            key='calculation_'+str(len(self.flow_calculations)+1)
            self.flow_calculations.append({'id':key,'name':name,'expression':runtime,
                'diagnostic_ids':sorted(value.diagnostics),'evidence_ids':[self.cite(node,'calculation')],
                'source_line':node.lineno})
            value.runtime={'op':'calc','id':key}
            return value

        def bind(self,target,value,env):
            if isinstance(target,(ast.Tuple,ast.List)) and getattr(value,'runtime',None) is not None:
                for index,item in enumerate(target.elts):
                    member=copy.deepcopy(value)
                    member.known=bool(value.known and isinstance(value.value,(tuple,list)) and len(value.value)==len(target.elts))
                    if member.known: member.value=value.value[index]
                    member.runtime={'op':'index','value':value.runtime,'index':literal(index)}
                    self.bind(item,member,env)
            else: super().bind(target,value,env)

        def lower(self,node,env):
            if node is None: return literal(None)
            if isinstance(node,ast.Constant): return literal(node.value)
            if isinstance(node,ast.Name):
                value=env.get(node.id)
                return copy.deepcopy(getattr(value,'runtime',None)) if value is not None else None
            if isinstance(node,(ast.List,ast.Tuple)):
                values=[self.lower(v,env) for v in node.elts]
                return {'op':'tuple' if isinstance(node,ast.Tuple) else 'list','values':values} if all(v is not None for v in values) else None
            if isinstance(node,ast.Dict):
                entries=[[self.lower(k,env),self.lower(v,env)] for k,v in zip(node.keys,node.values)]
                return {'op':'dict','entries':entries} if all(v is not None for pair in entries for v in pair) else None
            if isinstance(node,ast.Subscript):
                value=self.lower(node.value,env)
                if value is None: return None
                if isinstance(node.slice,ast.Slice):
                    return {'op':'slice','value':value,**{key:self.lower(v,env) if v else None for key,v in zip(('start','stop','step'),(node.slice.lower,node.slice.upper,node.slice.step))}}
                index=self.lower(node.slice,env)
                return {'op':'index','value':value,'index':index} if index is not None else None
            if isinstance(node,ast.BinOp):
                left,right=self.lower(node.left,env),self.lower(node.right,env)
                return {'op':'binary','operator':type(node.op).__name__,'left':left,'right':right} if left is not None and right is not None and isinstance(node.op,(ast.Add,ast.Sub,ast.Mult,ast.Div,ast.FloorDiv,ast.Mod)) else None
            if isinstance(node,ast.UnaryOp) and isinstance(node.op,(ast.Not,ast.USub)):
                value=self.lower(node.operand,env)
                return {'op':'not' if isinstance(node.op,ast.Not) else 'neg','value':value} if value is not None else None
            if isinstance(node,ast.BoolOp):
                values=[self.lower(v,env) for v in node.values]
                return {'op':'and' if isinstance(node.op,ast.And) else 'or','values':values} if all(v is not None for v in values) else None
            if isinstance(node,ast.Compare):
                values=[self.lower(v,env) for v in [node.left,*node.comparators]]
                return {'op':'compare','operators':[type(v).__name__ for v in node.ops],'values':values} if all(v is not None for v in values) else None
            if isinstance(node,ast.IfExp):
                parts={key:self.lower(v,env) for key,v in zip(('test','yes','no'),(node.test,node.body,node.orelse))}
                return {'op':'if',**parts} if all(v is not None for v in parts.values()) else None
            if isinstance(node,(ast.ListComp,ast.GeneratorExp,ast.DictComp)):
                local=copy.deepcopy(env)
                clauses=[]
                for generator in node.generators:
                    source=self.lower(generator.iter,local)
                    if source is None or generator.is_async: return None
                    self.flow_counter+=1
                    binding='item_'+str(self.flow_counter)
                    holder=self.merged('',[])
                    holder.runtime={'op':'item','id':binding}
                    self.bind(generator.target,holder,local)
                    where=[self.lower(v,local) for v in generator.ifs]
                    if any(v is None for v in where): return None
                    clauses.append({'binding':binding,'source':source,'where':where})
                value=self.lower(node.value if isinstance(node,ast.DictComp) else node.elt,local)
                key=self.lower(node.key,local) if isinstance(node,ast.DictComp) else None
                if value is None or isinstance(node,ast.DictComp) and key is None: return None
                return {'op':'dictcomp' if isinstance(node,ast.DictComp) else 'listcomp','clauses':clauses,'value':value,**({'key':key} if key else {})}
            if isinstance(node,ast.Call):
                called=ast.unparse(node.func)
                short=node.func.id if isinstance(node.func,ast.Name) else node.func.attr if isinstance(node.func,ast.Attribute) else ''
                root=called.split('.')[0]
                imported=self.parser_imports.get(root)
                qualified=imported[0]+called[len(root):] if imported and root not in env else called
                if qualified in {'date.today','datetime.date.today'} and not node.args and not node.keywords:
                    return {'op':'today'}
                if qualified in {'datetime.today','datetime.now','datetime.datetime.now','datetime.datetime.today'} and not node.args and not node.keywords:
                    return {'op':'now'}
                if (short=='timedelta' or qualified=='datetime.timedelta') and not node.args and all(k.arg in {'days','weeks'} for k in node.keywords):
                    days=literal(0)
                    for keyword in node.keywords:
                        part=self.lower(keyword.value,env)
                        if part is None: return None
                        if keyword.arg=='weeks': part={'op':'binary','operator':'Mult','left':part,'right':literal(7)}
                        days={'op':'binary','operator':'Add','left':days,'right':part}
                    return {'op':'duration','days':days}
                args=[self.lower(v,env) for v in node.args]
                if isinstance(node.func,ast.Name) and short not in self.defined_functions and short not in env and short in {'len','sum','min','max','abs','int','float','str','bool','round','list','tuple'} and not node.keywords and all(v is not None for v in args):
                    return {'op':'call','function':short,'args':args}
                if isinstance(node.func,ast.Attribute) and short=='get' and len(args) in (1,2) and all(v is not None for v in args):
                    container=self.lower(node.func.value,env)
                    return {'op':'get','value':container,'key':args[0],'default':args[1] if len(args)==2 else literal(None)} if container else None
                if short in {'fetchall','fetchone'} and isinstance(node.func,ast.Attribute):
                    pending=self.pending_queries.get(ast.unparse(node.func.value))
                    check=getattr(pending,'query_id',None)
                    if check:
                        rows={'op':'rows','check':check}
                        return rows if short=='fetchall' else {'op':'first','value':rows}
                if isinstance(node.func,ast.Name) and short in self.defined_functions and self.pure_depth<5:
                    function=next((v for v in self.tree.body if isinstance(v,ast.FunctionDef) and v.name==short),None)
                    if function and not function.args.vararg and not function.args.kwarg and all(v is not None for v in args):
                        parameters=[*function.args.posonlyargs,*function.args.args]
                        local=copy.deepcopy(env)
                        supplied={p.arg:v for p,v in zip(parameters,args)}
                        supplied.update({k.arg:self.lower(k.value,env) for k in node.keywords if k.arg})
                        defaults=dict(zip([p.arg for p in parameters[-len(function.args.defaults):]],function.args.defaults)) if function.args.defaults else {}
                        for parameter in parameters:
                            value=supplied.get(parameter.arg)
                            if value is None and parameter.arg in defaults: value=self.lower(defaults[parameter.arg],env)
                            if value is None: break
                            holder=self.merged('',[]);holder.runtime=value;local[parameter.arg]=holder
                        else:
                            self.pure_depth+=1
                            try: return self.pure_block(function.body,local)
                            finally: self.pure_depth-=1
            return None

        def pure_block(self,nodes,env):
            for index,node in enumerate(nodes):
                if isinstance(node,ast.Return): return self.lower(node.value,env)
                if isinstance(node,ast.Assign) and all(isinstance(t,ast.Name) for t in node.targets):
                    value=self.lower(node.value,env)
                    if value is None: return None
                    for target in node.targets:
                        holder=self.merged('',[]);holder.runtime=value;env[target.id]=holder
                elif isinstance(node,ast.If):
                    test=self.lower(node.test,env)
                    yes=self.pure_block([*node.body,*nodes[index+1:]],copy.deepcopy(env))
                    no=self.pure_block([*node.orelse,*nodes[index+1:]],copy.deepcopy(env))
                    return {'op':'if','test':test,'yes':yes,'no':no} if test is not None and yes is not None and no is not None else None
                elif isinstance(node,ast.Pass) or isinstance(node,ast.Expr) and isinstance(node.value,ast.Constant): continue
                else: return None
            return literal(None)

        def pieces(self,node,env):
            if isinstance(node,ast.Name):
                value=env.get(node.id)
                if value and value.known and isinstance(value.value,str): return [value.value]
                return getattr(value,'sql_parts',None)
            if isinstance(node,ast.Constant) and isinstance(node.value,str): return [node.value]
            if isinstance(node,ast.BinOp) and isinstance(node.op,ast.Add):
                left,right=self.pieces(node.left,env),self.pieces(node.right,env)
                return [*left,*right] if left is not None and right is not None else None
            if isinstance(node,ast.JoinedStr):
                parts=[]
                for item in node.values:
                    if isinstance(item,ast.Constant): parts.append(item.value)
                    elif item.format_spec is None and item.conversion in (-1,115):
                        part=self.lower(item.value,env)
                        if part is None: return None
                        parts.append(part)
                    else: return None
                return parts
            if isinstance(node,ast.Call) and isinstance(node.func,ast.Attribute) and node.func.attr=='format':
                template=self.pieces(node.func.value,env)
                if template is None or not all(isinstance(v,str) for v in template): return None
                positional=[self.lower(v,env) for v in node.args]
                named={v.arg:self.lower(v.value,env) for v in node.keywords if v.arg}
                parts=[];automatic=0
                try:
                    for text,field,spec,conversion in string.Formatter().parse(''.join(template)):
                        parts.append(text)
                        if field is None: continue
                        if spec or conversion or not re.fullmatch(r'[A-Za-z_][A-Za-z_0-9]*|[0-9]*',field): return None
                        if field=='': value=positional[automatic];automatic+=1
                        elif field.isdigit(): value=positional[int(field)]
                        else: value=named[field]
                        if value is None: return None
                        parts.append(value)
                except (ValueError,KeyError,IndexError): return None
                return parts
            return None

        def sql_value(self,expression):
            expression=self.expand(expression)
            if not expression: return None
            if expression['op']=='today': return 'CURRENT_DATE()'
            if expression['op']=='now': return 'CURRENT_TIMESTAMP(6)'
            if expression['op']=='binary' and expression['operator'] in {'Add','Sub'}:
                left,right=expression['left'],expression['right']
                if right.get('op')=='duration':
                    base=self.sql_value(left)
                    try: days=Evaluation({}).run(right['days'])
                    except Exception: return None
                    if base and type(days) is int and abs(days)<=36600:
                        return '('+base+(' + ' if expression['operator']=='Add' else ' - ')+'INTERVAL '+str(days)+' DAY)'
            if expression['op']=='binary' and expression['operator'] in {'Add','Sub','Mult','Div'}:
                left,right=self.sql_value(expression['left']),self.sql_value(expression['right'])
                if left is not None and right is not None:
                    return '('+left+{'Add':' + ','Sub':' - ','Mult':' * ','Div':' / '}[expression['operator']]+right+')'
            if expression['op']=='call' and expression['function']=='len' and len(expression['args'])==1:
                rows=expression['args'][0]
                if rows.get('op')=='rows':
                    check=next((c for c in self.diagnostics if c['id']==rows['check']),None)
                    if check and not check.get('result_limit'):
                        return '(SELECT COUNT(*) FROM ('+check['operation']+') AS __rca_source_rows)'
            try:
                result=Evaluation({}).run(expression)
                if type(result) is int or type(result) is float and math.isfinite(result): return str(result)
                if isinstance(result,str) and re.fullmatch(r'[A-Za-z0-9_ .:/@+-]{0,128}',result): return "'"+result+"'"
            except (InvalidMeasurement,KeyError,TypeError,ValueError,ZeroDivisionError): pass
            return None

        def parameter_parts(self,text,parameters):
            parameters=self.expand(parameters)
            if not parameters or parameters.get('op') not in {'tuple','list','dict'}: return None
            values=parameters.get('values',[])
            named={key['value']:value for key,value in parameters.get('entries',[]) if key.get('op')=='literal' and isinstance(key.get('value'),str)}
            result=[]
            start=index=count=0
            quote=''
            while index<len(text):
                char=text[index]
                if quote:
                    if char=='\\': index+=2;continue
                    if char==quote:
                        if index+1<len(text) and text[index+1]==quote: index+=2;continue
                        quote=''
                elif char in "'\"`": quote=char
                elif text.startswith(('--','/*','#'),index): return None
                elif text.startswith('%s',index):
                    if count>=len(values): return None
                    result.extend([text[start:index],values[count]])
                    count+=1;index+=2;start=index;continue
                elif text.startswith('%(',index):
                    match=re.match(r'%\(([^)]+)\)s',text[index:])
                    if not match or match[1] not in named: return None
                    result.extend([text[start:index],named[match[1]]])
                    count+=1;index+=len(match[0]);start=index;continue
                index+=1
            if quote or (not named and count!=len(values)): return None
            return [*result,text[start:]]

        def normalize_sql(self,parts):
            if not parts: return None
            expressions=[]
            fragments=[]
            for part in parts:
                if isinstance(part,str): fragments.append(part)
                else:
                    fragments.append('__RCA_BIND_'+str(len(expressions))+'__')
                    expressions.append(part)
            text=''.join(fragments).strip().removesuffix(';').strip()
            if not text.upper().startswith('SELECT'): return None
            limit=None
            final=re.search(r'\bLIMIT\s+(__RCA_BIND_(\d+)__)\s*$',text,re.I)
            if final:
                # Preserve effective source rows by slicing a complete ordered
                # diagnostic result. Never substitute an arbitrary fixed LIMIT.
                prefix=text[:final.start()]
                if sql_state(text,final.start())!=('',0): return None
                if not re.search(r'\bORDER\s+BY\b',prefix,re.I): return None
                limit=expressions[int(final[2])]
                if not refs(self.expand(limit)): return None
                text=prefix.rstrip()
            uses_date=False
            for index,expression in enumerate(expressions):
                marker='__RCA_BIND_'+str(index)+'__'
                if marker not in text: continue
                value=self.sql_value(expression)
                if value is None: return None
                if 'CURRENT_DATE()' in value or 'CURRENT_TIMESTAMP(' in value: uses_date=True
                # Only standalone SQL values are normalized, never identifiers
                # or fragments of string literals.
                full_literal=re.search(r"(['\"])"+marker+r'\1',text)
                if full_literal:
                    state=sql_state(text,full_literal.start())
                    if state is None or state[0]: return None
                    text=text[:full_literal.start()]+value+text[full_literal.end():]
                if marker not in text: continue
                state=sql_state(text,text.index(marker))
                if state is None or state[0] or re.search(r'\b(?:FROM|JOIN|AS|LIMIT|OFFSET)\s*'+marker,text,re.I): return None
                if re.search(r'\b(?:ORDER|GROUP)\s+BY\s*'+marker,text,re.I): return None
                text=text.replace(marker,value)
            return text,limit,uses_date

        def expression(self,node,env):
            is_execute=isinstance(node,ast.Call) and isinstance(node.func,ast.Attribute) and node.func.attr=='execute' and node.args
            before=len(self.diagnostics)
            normalization=None
            if is_execute:
                operation=env.get(node.args[0].id) if isinstance(node.args[0],ast.Name) else None
                parts=self.pieces(node.args[0],env)
                dependent_parameters=False
                if len(node.args)==2 and parts and all(isinstance(v,str) for v in parts):
                    parameters=self.lower(node.args[1],env)
                    expanded=self.expand(parameters)
                    if parameters is not None and (refs(expanded) or '"op": "today"' in json.dumps(expanded)):
                        bound=self.parameter_parts(''.join(parts),parameters)
                        if bound is not None:
                            parts=bound
                            dependent_parameters=True
                if parts and any(not isinstance(v,str) for v in parts) and (operation is None or not operation.known or dependent_parameters):
                    normalization=self.normalize_sql(parts)
                if normalization:
                    text,limit,uses_date=normalization
                    replaced=copy.deepcopy(node)
                    if dependent_parameters: replaced.args=replaced.args[:1]
                    replaced.args[0]=ast.copy_location(ast.Constant(text),node.args[0])
                    # Copy dependency metadata, while keeping the approved SQL
                    # literal and its original source citation separate.
                    value=copy.deepcopy(operation) if operation else self.merged(ast.unparse(node.args[0]),[])
                    if dependent_parameters:
                        value=self.merged(value.text,[value,self.expression(node.args[1],env)])
                    value.known,value.value=True,text
                    value.runtime=literal(text)
                    value.sql_parts=[text]
                    temporary='__rca_resolved_query'
                    shadow={**env,temporary:value}
                    replaced.args[0]=ast.copy_location(ast.Name(id=temporary,ctx=ast.Load()),node.args[0])
                    result=super().expression(replaced,shadow)
                else: result=super().expression(node,env)
            else: result=super().expression(node,env)
            runtime=self.lower(node,env)
            if runtime is None and result.known and type(result.value) in (str,int,float,bool,type(None)):
                runtime=literal(result.value)
            if runtime is not None:
                result.runtime=runtime
                if not refs(self.expand(runtime)) and not self.flow_loops:
                    try:
                        folded=Evaluation({'calculations':self.flow_calculations}).run(runtime)
                        if type(folded) in (str,int,float,bool,type(None)):
                            result.known,result.value=True,folded
                    except (InvalidMeasurement,TypeError,ValueError,KeyError,IndexError,ZeroDivisionError,OverflowError,RecursionError): pass
            parts=self.pieces(node,env)
            if parts is not None: result.sql_parts=parts
            if len(self.diagnostics)>before and is_execute:
                check=self.diagnostics[-1]
                result.query_id=check['id']
                if normalization:
                    check['source_operation']=ast.unparse(node.args[0])
                    check['result_limit']=normalization[1]
                    check['database_calendar']=normalization[2]
                    check['dependency_ids']=sorted(refs(self.expand(normalization[1]))) if normalization[1] else []
                    self.flow_active=True
                self.flow_checks[check['id']]={k:copy.deepcopy(v) for k,v in check.items() if k in {'id','result_limit'}}
                self.pending_queries[ast.unparse(node.func.value)]=copy.deepcopy(result)
            return result

        def statements(self,statements,env,conditions=()):
            for node in statements:
                if isinstance(node,ast.Expr) and isinstance(node.value,ast.Call) and isinstance(node.value.func,ast.Attribute) and node.value.func.attr in {'append','extend'} and isinstance(node.value.func.value,ast.Name) and len(node.value.args)==1:
                    owner=node.value.func.value.id
                    previous=env.get(owner)
                    argument=self.expression(node.value.args[0],env)
                    runtime=getattr(argument,'runtime',None)
                    if previous is not None and runtime is not None and self.flow_loops:
                        loop=self.flow_loops[-1]
                        where=[]
                        for text,guard in conditions[loop['guards']:]:
                            part=getattr(guard,'runtime',None)
                            if part is None: runtime=None;break
                            where.append({'op':'not','value':part} if text.startswith('not (') else part)
                        if runtime is not None:
                            loop['entries'].setdefault(owner,[]).append({'value':runtime,'extend':node.value.func.attr=='extend','where':where})
                    result=self.merged(owner,[previous,argument]) if previous is not None else argument
                    result.evidence.add(self.cite(node,'assignment'))
                    env[owner]=result
                    continue
                if isinstance(node,ast.For):
                    iterable=self.expression(node.iter,env)
                    runtime=getattr(iterable,'runtime',None)
                    if runtime is not None and not iterable.known:
                        self.flow_counter+=1
                        binding='loop_'+str(self.flow_counter)
                        member=copy.deepcopy(iterable)
                        member.known=False
                        member.runtime={'op':'item','id':binding}
                        local=copy.deepcopy(env)
                        self.bind(node.target,member,local)
                        loop={'binding':binding,'source':runtime,'guards':len(conditions),'entries':{}}
                        self.flow_loops.append(loop)
                        self.statements(node.body,local,conditions)
                        self.flow_loops.pop()
                        for owner,entries in loop['entries'].items():
                            initial=getattr(env.get(owner),'runtime',None)
                            if initial is None: continue
                            result=copy.deepcopy(local[owner])
                            result.runtime={'op':'collect','source':runtime,'binding':binding,'initial':initial,'entries':entries}
                            env[owner]=self.record(owner,result,node)
                            self.flow_active=True
                        self.statements(node.orelse,env,conditions)
                        continue
                branch=self.lower(node.test,env) if isinstance(node,ast.If) else None
                if branch is not None: self.flow_branches.append(branch)
                super().statements([node],env,conditions)
                if branch is not None: self.flow_branches.pop()
                if isinstance(node,ast.If):
                    for key,value in env.items():
                        runtime=getattr(value,'runtime',None)
                        if runtime is not None and runtime.get('op')=='if':
                            value.unknown_inputs.discard('branch-dependent value '+key)
                            self.record(key,value,node)
                if isinstance(node,(ast.Assign,ast.AnnAssign)):
                    targets=node.targets if isinstance(node,ast.Assign) else [node.target]
                    for target in targets:
                        if isinstance(target,ast.Name) and target.id in env: self.record(target.id,env[target.id],node)

        def add_rule(self,node,conditions,outcome,env):
            before=len(self.rules)
            super().add_rule(node,conditions,outcome,env)
            if len(self.rules)>before:
                expressions=[]
                for text,value in conditions:
                    part=getattr(value,'runtime',None)
                    if part is None: break
                    expressions.append({'op':'not','value':part} if text.startswith('not (') else part)
                else:
                    self.flow_rules.append({'id':self.rules[-1]['id'],'outcome':outcome,'expression':{'op':'and','values':expressions}})

        def build(self,validate=True):
            plan=super().build(validate=False)
            if self.flow_active and len(self.flow_rules)!=len(plan['rules']):
                self.unknown(self.tree.body[0],'Some decision calculations could not be translated into the data-flow model. Review the source helper or expression before claiming that condition is assessed.','UNRESOLVED_RULE_COVERAGE')
                import hashlib
                for item in self.unknowns:
                    if 'id' not in item:
                        identity=json.dumps(item,sort_keys=True,separators=(',',':'))
                        item['id']='warning_'+hashlib.sha256(identity.encode()).hexdigest()[:24]
                        item['acknowledgeable']=item['code']=='UNRESOLVED_RULE_COVERAGE'
            plan['dataflow']={'version':1,'active':self.flow_active,'calculations':self.flow_calculations,
                'checks':list(self.flow_checks.values()),'rules':self.flow_rules,
                'complete':bool(plan['rules']) and len(self.flow_rules)==len(plan['rules']),
                'clock_basis':'DATABASE_CALENDAR_FOR_CURRENT_DIAGNOSTICS'}
            import sys
            module=sys.modules[base.__module__]
            plan['evidence']=list(self.evidence.values())
            plan['coverage_review']=module.coverage_review(plan,None)
            plan['onboarding_review']=module.onboarding_review(plan)
            if validate:
                module.validate_plan(plan,self.source)
            return plan
    return DependencyBuilder


class Description:
    def __init__(self,flow):
        self.calculations={v['id']:v for v in flow['calculations']}
        self.inline=set()
        for entry in flow['calculations']:
            expression=entry['expression']
            if expression['op']=='if':
                for branch in ('yes','no'):
                    child=expression[branch]
                    if child.get('op')=='calc' and self.calculations[child['id']]['name']==entry['name']:
                        self.inline.add(child['id'])

    def label(self,key):
        name=self.calculations[key]['name']
        return re.sub(r'(?<=[A-Za-z])(?=\d)|(?<=\d)(?=[A-Za-z])',' ',name.replace('_',' '))

    def expanded(self,node,seen=None):
        if not isinstance(node,dict): return node
        seen=set() if seen is None else seen
        if len(seen)>80: return node
        if node.get('op')=='calc':
            key=node['id']
            if key in seen: return node
            return self.expanded(self.calculations[key]['expression'],seen|{key})
        return {key:self.expanded(value,seen) if isinstance(value,dict) else
                [self.expanded(v,seen) for v in value] if isinstance(value,list) else value
                for key,value in node.items()}

    def expression(self,node,bindings=None,depth=0):
        if depth>30 or not isinstance(node,dict): return 'an unresolved source calculation'
        bindings=bindings or {}
        def text(value): return self.expression(value,bindings,depth+1)
        op=node['op']
        if op=='calc':
            entry=self.calculations[node['id']]
            if node['id'] in self.inline: return text(entry['expression'])
            if entry['expression']['op']=='literal': return text(entry['expression'])
            if entry['expression']['op']=='list' and not entry['expression']['values']: return 'an empty list'
            return self.label(node['id'])
        if op=='literal': return 'NULL' if node['value'] is None else repr(node['value']) if isinstance(node['value'],str) else str(node['value'])
        if op=='rows': return 'the returned rows from '+node['check'].replace('check_','step ')
        if op=='item': return bindings.get(node['id'],'that row')
        if op=='first': return 'the first row of '+text(node['value'])
        if op=='index':
            index=node['index']
            return ('column '+str(index['value']+1)+' of '+text(node['value']) if index.get('op')=='literal' and type(index.get('value')) is int and index['value']>=0 else 'the element at '+text(index)+' in '+text(node['value']))
        if op=='slice':
            start,stop,step=node.get('start'),node.get('stop'),node.get('step')
            if start is None and stop and stop['op']=='literal' and type(stop['value']) is int and stop['value']>=0 and step is None:
                return 'the first '+str(stop['value'])+' rows of '+text(node['value'])+', preserving their order'
            if start and start['op']=='neg' and stop is None and step is None:
                return 'the last '+text(start['value'])+' rows of '+text(node['value'])+', preserving their order'
            return 'the source slice of '+text(node['value'])+' (start '+text(start or literal(None))+', stop '+text(stop or literal(None))+', step '+text(step or literal(None))+')'
        if op in {'list','tuple'}: return '('+', '.join(text(v) for v in node['values'])+')'
        if op=='get': return 'lookup in '+text(node['value'])+' at '+text(node['key'])+' (default '+text(node['default'])+')'
        if op=='not':
            child=node['value']
            inverse={'Eq':'NotEq','NotEq':'Eq','Gt':'LtE','GtE':'Lt','Lt':'GtE','LtE':'Gt','Is':'IsNot','IsNot':'Is','In':'NotIn','NotIn':'In'}
            if child.get('op')=='compare' and len(child['operators'])==1:
                return text({**child,'operators':[inverse[child['operators'][0]]]})
            return 'not ('+text(child)+')'
        if op=='neg': return '−'+text(node['value'])
        if op=='binary': return '('+text(node['left'])+{'Add':' + ','Sub':' − ','Mult':' × ','Div':' / ','FloorDiv':' // ','Mod':' modulo '}[node['operator']]+text(node['right'])+')'
        if op in {'and','or'}: return (' and ' if op=='and' else ' or ').join('('+text(v)+')' for v in node['values'])
        if op=='compare':
            operators={'Eq':'=','NotEq':'≠','Lt':'<','LtE':'≤','Gt':'>','GtE':'≥','Is':'is','IsNot':'is not','In':'is in','NotIn':'is not in'}
            return ' and '.join(text(a)+' '+operators[k]+' '+text(b) for a,k,b in zip(node['values'],node['operators'],node['values'][1:]))
        if op=='call':
            function=node['function']
            if function=='len': return 'the number of '+text(node['args'][0])
            if function=='sum':
                part=node['args'][0]
                if part.get('op')=='listcomp' and len(part['clauses'])==1 and not part['clauses'][0]['where']:
                    clause=part['clauses'][0]
                    item=part['value']
                    if item.get('op')=='index' and item['value'].get('op')=='item' and item['index'].get('op')=='literal':
                        return 'the sum of column '+str(item['index']['value']+1)+' across '+text(clause['source'])
                return 'the sum of '+text(part)
            return function+'('+', '.join(text(v) for v in node['args'])+')'
        if op=='if': return text(node['yes'])+' when '+text(node['test'])+'; otherwise '+text(node['no'])
        if op=='today': return 'the current database calendar date'
        if op=='now': return 'the current database timestamp'
        if op=='duration': return text(node['days'])+' day(s)'
        if op in {'listcomp','dictcomp'}:
            local=dict(bindings)
            descriptions=[]
            for clause in node['clauses']:
                source=self.expression(clause['source'],local,depth+1)
                local[clause['binding']]='each row in '+source
                condition=' and '.join(self.expression(v,local,depth+1) for v in clause['where'])
                descriptions.append(source+(' where '+condition if condition else ''))
            if op=='dictcomp': return 'a lookup from '+', then '.join(descriptions)+', keyed by '+self.expression(node['key'],local,depth+1)+', storing '+self.expression(node['value'],local,depth+1)
            if node['value']['op']=='item': return 'the rows from '+', then '.join(descriptions)
            return self.expression(node['value'],local,depth+1)+' for '+', then '.join(descriptions)
        if op=='collect':
            local={**bindings,node['binding']:'that row'}
            entries=[]
            for entry in node['entries']:
                condition=' and '.join(self.expression(v,local,depth+1) for v in entry['where'])
                entries.append(('extend with ' if entry['extend'] else 'append ')+self.expression(entry['value'],local,depth+1)+(' when '+condition if condition else ''))
            return 'start with '+text(node['initial'])+'; for each row in '+text(node['source'])+', '+'; '.join(entries)
        return 'an unsupported source expression'


def render_dependency_sop(plan,dag_id):
    flow=plan.get('dataflow',{})
    if not flow.get('active'): return None
    description=Description(flow)
    target=plan['target']
    lines=['# INVESTIGATION SOP FOR '+dag_id,'','Component ID: '+dag_id,'Operating mode: INVESTIGATE_ONLY',
           'Registered '+target['type']+' target: '+target['id'],'- Procedure basis: validated DAG source.','',
           'Assess the current state using the following checks and source-derived calculations. Complete every required check.']
    if any(c.get('database_calendar') for c in plan['diagnostics']):
        lines+=['','Relative dates use the registered database calendar for this current-state procedure. The source uses the Airflow host date; this normalization does not establish that the two clocks share a timezone. Do not use these checks to reconstruct a historical run.']
    if plan.get('airflow_variables'):
        lines+=['','Configured values used for this procedure:']
        lines.extend('- '+v['name']+': '+(json.dumps(v.get('value'),ensure_ascii=False) if v.get('confirmed') else 'UNCONFIRMED') for v in plan['airflow_variables'])
    review=plan.get('coverage_review',{})
    if review.get('accepted'):
        lines+=['','Accepted limited coverage: report observations, but the overall result must remain INCONCLUSIVE.',
                '<!-- RCA_LIMITED_COVERAGE_V1:'+review['token']+' -->']
    for index,check in enumerate(plan['diagnostics'],1):
        required={key for rule in plan['rules'] for key in rule['diagnostic_ids']}
        for dependent in plan['diagnostics']: required.update(dependent.get('dependency_ids',[]))
        prefix='Optional supporting observation: ' if required and check['id'] not in required else ''
        lines+=['',str(index)+'. '+prefix+"Run "+check['tool']+" on target '"+check['target_id']+"' with this exact "+('read-only query:' if check['tool']=='query_database' else 'command:'),
                '', '```sql' if check['tool']=='query_database' else '```sh',check['operation'],'```']
        if check.get('result_limit'):
            lines+=['','Before using this result, retain only the first '+description.expression(description.expanded(check['result_limit']))+' rows, in the returned order. This preserves the source runtime LIMIT. The diagnostic retrieves the ordered rows before applying that limit; require a complete, untruncated result.']
    wanted=set()
    for rule in flow['rules']: wanted.update(calc_refs(rule['expression']))
    for check in flow['checks']:
        if check.get('result_limit'): wanted.update(calc_refs(check['result_limit']))
    queue=list(wanted)
    while queue:
        key=queue.pop()
        entry=description.calculations.get(key)
        if entry:
            for child in calc_refs(entry['expression'])-wanted: wanted.add(child);queue.append(child)
    lines+=['','Calculate and interpret:']
    for entry in flow['calculations']:
        if entry['id'] not in wanted or entry['id'] in description.inline or entry['expression']['op']=='literal': continue
        if entry['expression']['op']=='list' and not entry['expression']['values']: continue
        lines.append('- '+description.label(entry['id'])+': '+description.expression(entry['expression'])+'.')
    lines+=['','Classification:']
    for rule in flow['rules']:
        outcome='NO_REMEDIATION_REQUIRED' if rule['outcome']=='SOURCE_NO_ALERT' else rule['outcome']
        lines.append('- If '+description.expression(rule['expression'])+': '+outcome+'.')
    if not flow.get('complete'):
        lines.append('- Some source rules are not fully translated. Those conditions remain unassessed; do not infer health from them.')
    lines+=['- If no classification branch is established, use INCONCLUSIVE. A source branch that skips evaluation, including absent production or no qualifying measurements, does not establish model health.',
            '- Missing, NULL, nonnumeric or nonfinite required measurements, invalid calculations, failed checks or truncated rows are INCONCLUSIVE. Never convert missing data to zero unless that exact default is specified in a calculation above.',
            '- Report the current measurements and selected branch. A healthy current observation does not establish the cause or exact recovery time of an earlier alert.']
    if plan['confirmation_questions']: lines+=['','Draft only: complete the remaining configuration confirmations before activation.']
    if plan['unknowns']:
        lines+=['','Review limitations:',*['- '+item['reason'] for item in plan['unknowns']]]
    lines+=['','Do not run database writes, restarts, process termination, DAG triggers, notifications or other state-changing operations. No automatic remediation is registered by this SOP.']
    return '\n'.join(lines)

# RCA_STORED_REPORT_WORKFLOWS_V1
# Generic source-backed reporting scope. No pasted function is executed.
_report_base_builder = builder_class
_report_base_renderer = render_dependency_sop
_report_base_evaluator = evaluate_plan


def _report_names(node):
    if node is None: return set()
    return {part.id for part in ast.walk(node) if isinstance(part, ast.Name) and isinstance(part.ctx, ast.Load)}


def _report_writes(node):
    result = {part.id for part in ast.walk(node) if isinstance(part, ast.Name) and isinstance(part.ctx, ast.Store)}
    for part in ast.walk(node):
        if isinstance(part, ast.Call) and isinstance(part.func, ast.Attribute) and part.func.attr in {'append', 'extend', 'update', 'add'}:
            owner = part.func.value
            while isinstance(owner, (ast.Subscript, ast.Attribute)):
                owner = owner.value
            if isinstance(owner, ast.Name): result.add(owner.id)
        if isinstance(part, (ast.Assign, ast.AugAssign, ast.AnnAssign)):
            for target in part.targets if isinstance(part, ast.Assign) else [part.target]:
                while isinstance(target, (ast.Subscript, ast.Attribute)): target = target.value
                if isinstance(target, ast.Name): result.add(target.id)
    return result


@lru_cache(maxsize=8)
def builder_class(base):
    parent = _report_base_builder(base)

    class ReportBuilder(parent):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.report_functions = {node.name: node for node in self.tree.body if isinstance(node, ast.FunctionDef)}
            self.report_email_names = {name for name, pair in self.parser_imports.items()
                                       if pair[0] == 'airflow.utils.email.send_email'}
            # A locally redefined import is not the recognized Airflow email sink.
            self.report_email_names -= set(self.report_functions)
            self.report_functions_with_sink = set()
            while True:
                expanded = self.report_functions_with_sink | {
                    name for name, function in self.report_functions.items()
                    if any(isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                           and node.func.id in self.report_email_names | self.report_functions_with_sink
                           for node in ast.walk(function))}
                if expanded == self.report_functions_with_sink: break
                self.report_functions_with_sink = expanded
            roots = [node for node in self.tree.body if not isinstance(node, (ast.FunctionDef, ast.ClassDef))]
            self.report_roots = {node.func.id for root in roots for node in ast.walk(root)
                                 if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)}
            self.report_enabled = (self.target.get('type') == 'DATABASE'
                and bool(self.report_functions_with_sink & self.reachable)) and not base.contains_alert(
                [function for name, function in self.report_functions.items() if name in self.reachable])
            self.report_needed = {name: set() for name in self.report_functions}
            self.report_paths = []
            self.report_details = []
            self.report_guards = {}
            self.report_stack = []
            self.report_global_env = {}
            if self.report_enabled: self.report_control_dependencies()

        def report_control_dependencies(self):
            # Backward slice of notification CONTROL inputs, excluding payload.
            # A field used in an email body is not thereby a classification input.
            for _ in range(10):
                changed = False
                for name, function in self.report_functions.items():
                    needed = set(self.report_needed[name])
                    def visit(nodes, guards=()):
                        for node in nodes:
                            if isinstance(node, ast.If):
                                visit(node.body, (*guards, node.test)); visit(node.orelse, (*guards, node.test))
                            elif isinstance(node, (ast.For, ast.While, ast.With, ast.Try)):
                                visit(node.body, guards)
                                visit(getattr(node, 'orelse', []), guards)
                            else:
                                for call in ast.walk(node):
                                    if not isinstance(call, ast.Call) or not isinstance(call.func, ast.Name): continue
                                    called = call.func.id
                                    if called not in self.report_email_names | self.report_functions_with_sink: continue
                                    for guard in guards: needed.update(_report_names(guard))
                                    if called in self.report_functions:
                                        parameters = self.report_functions[called].args.args
                                        supplied = {p.arg: v for p, v in zip(parameters, call.args)}
                                        supplied.update({p.arg: p.value for p in call.keywords if p.arg})
                                        for key in self.report_needed[called]:
                                            if key in supplied: needed.update(_report_names(supplied[key]))
                    visit(function.body)
                    edges = []
                    for node in ast.walk(function):
                        if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                            edges.append((_report_writes(node), _report_names(node.value)))
                        elif isinstance(node, ast.For):
                            edges.append((_report_writes(node.target), _report_names(node.iter)))
                        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in {'append', 'extend', 'update', 'add'}:
                            edges.append((_report_writes(node), set().union(*(_report_names(a) for a in node.args))))
                    while True:
                        expanded = needed | set().union(*(reads for writes, reads in edges if writes & needed))
                        if expanded == needed: break
                        needed = expanded
                    if needed != self.report_needed[name]: changed = True; self.report_needed[name] = needed
                if not changed: break

        def report_has_sink(self, node):
            return any(isinstance(part, ast.Call) and isinstance(part.func, ast.Name)
                       and part.func.id in self.report_email_names | self.report_functions_with_sink
                       for part in ast.walk(node))

        def unknown(self, node, reason, code='SOURCE_UNRESOLVED'):
            if (getattr(self, 'report_enabled', False) and isinstance(node, ast.If)
                    and reason.startswith('A query cursor has branch-dependent results.')):
                function = self.report_functions.get(self.report_stack[-1]) if self.report_stack else None
                # Only suppress the dead cursor warning when no later source
                # fetch can consume the merged cursor result.
                if function and not any(isinstance(part, ast.Call) and isinstance(part.func, ast.Attribute)
                        and part.func.attr in {'fetchall', 'fetchone', 'fetchmany'}
                        and part.lineno > node.end_lineno for part in ast.walk(function)):
                    return
            return super().unknown(node, reason, code)

        def expression(self, node, env):
            if self.report_enabled and isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                called = node.func.id
                if called in self.report_email_names and called not in env:
                    # Only data-controlled notifications establish report rules.
                    conditions = [(text, value) for text, value in self.active_conditions
                                  if not (value.known and value.value is True)]
                    values = [value for _, value in conditions]
                    merged = self.merged('notification eligibility', values)
                    if conditions and merged.diagnostics:
                        before = len(self.rules)
                        before_flow = len(self.flow_rules)
                        self.add_rule(node, conditions, 'MANUAL_REVIEW_REQUIRED', env)
                        if len(self.rules) > before:
                            self.flow_active = True
                            if len(self.flow_rules) > before_flow:
                                self.report_paths.append((node, merged, self.flow_rules[-1]['expression']))
                            else:
                                self.unknown(node, 'A notification control expression could not be translated; its decision remains unassessed.', 'UNRESOLVED_RULE_COVERAGE')
                    return self.merged('notification payload (not executed)', [])
                if called in self.report_functions_with_sink and called not in self.report_roots:
                    function = self.report_functions[called]
                    if len(self.report_stack) >= 10 or called in self.report_stack or function.args.vararg or function.args.kwarg:
                        self.unknown(node, 'A notification helper has unsupported recursive or variadic control flow.', 'UNRESOLVED_RULE_COVERAGE')
                        return self.merged('unsupported notification helper', [])
                    supplied = {p.arg: self.expression(value, env) for p, value in zip(function.args.args, node.args)}
                    supplied.update({part.arg: self.expression(part.value, env) for part in node.keywords if part.arg})
                    needed = self.report_needed[called]
                    if any(p.arg in needed and p.arg not in supplied for p in function.args.args):
                        self.unknown(node, 'A notification helper control argument is missing.', 'UNRESOLVED_RULE_COVERAGE')
                        return self.merged('missing notification helper input', [])
                    # Function free names resolve in the module, not the caller's
                    # task-local scope. Only explicit arguments cross the call.
                    local = copy.deepcopy(self.report_global_env); local.update(copy.deepcopy(supplied))
                    saved = self.active_conditions
                    self.report_stack.append(called)
                    try: self.statements(function.body, local, saved)
                    finally: self.report_stack.pop(); self.active_conditions = saved
                    return self.merged('reviewed notification control', list(supplied.values()))
            before = len(self.diagnostics)
            result = super().expression(node, env)
            if self.report_enabled and len(self.diagnostics) > before:
                expressions = []
                for text, guard in self.active_conditions:
                    value = getattr(guard, 'runtime', None)
                    if value is None: break
                    expressions.append({'op': 'not', 'value': value} if text.startswith('not (') else value)
                else:
                    if expressions:
                        self.report_guards[self.diagnostics[-1]['id']] = {'op': 'and', 'values': expressions}
            return result

        def lower(self, node, env):
            result = super().lower(node, env)
            if self.report_enabled and result and result.get('op') == 'call' and result.get('function') == 'len':
                def shape(value):
                    value = self.expand(value)
                    if not value: return None
                    if value.get('op') in {'list', 'tuple'}: return len(value['values'])
                    if value.get('op') == 'binary' and value.get('operator') == 'Add':
                        left, right = shape(value['left']), shape(value['right'])
                        if left is not None and right is not None: return left + right
                    return None
                if len(result.get('args', [])) == 1:
                    size = shape(result['args'][0])
                    if size is not None: return literal(size)
            return result

        def statements(self, statements, env, conditions=()):
            root = statements is self.tree.body
            for node in statements:
                if self.report_enabled and isinstance(node, ast.FunctionDef):
                    if not self.report_stack: self.report_global_env = copy.deepcopy(env)
                    if node.name in self.report_functions_with_sink and node.name not in self.report_roots:
                        continue  # Analyze helpers at their call with real symbolic arguments.
                    self.report_stack.append(node.name)
                    try: super().statements([node], env, conditions)
                    finally: self.report_stack.pop()
                    continue
                needed = self.report_needed.get(self.report_stack[-1], set()) if self.report_stack else set()
                if (self.report_enabled and isinstance(node, ast.For) and not self.report_has_sink(node)
                        and not (_report_writes(node) & needed)):
                    self.report_details.append({'role': 'REPORT_ENRICHMENT', 'source_line': node.lineno,
                        'evidence_ids': [self.cite(node, 'report_enrichment')],
                        'reason': 'Excluded from stored-warning assessment: enriches or formats the report payload; no traced notification decision depends on these outputs.'})
                    continue
                append = (self.report_enabled and isinstance(node, ast.Expr) and isinstance(node.value, ast.Call)
                          and isinstance(node.value.func, ast.Attribute) and node.value.func.attr == 'append'
                          and isinstance(node.value.func.value, ast.Name) and len(node.value.args) == 1)
                if append:
                    owner = node.value.func.value.id
                    previous = copy.deepcopy(getattr(env.get(owner), 'runtime', None))
                    argument = self.lower(node.value.args[0], env)
                super().statements([node], env, conditions)
                if append and previous is not None and argument is not None and owner in env:
                    env[owner].runtime = {'op': 'binary', 'operator': 'Add', 'left': previous,
                                          'right': {'op': 'list', 'values': [argument]}}
                    self.record(owner, env[owner], node)
            if root and self.report_enabled and self.report_paths:
                node = self.report_paths[0][0]
                value = self.merged('any notification-eligible condition', [part[1] for part in self.report_paths])
                expression = {'op': 'or', 'values': [part[2] for part in self.report_paths]}
                value.runtime = expression
                self.add_rule(node, [('not (any notification-eligible condition)', value)], 'SOURCE_NO_ALERT', env)

        def build(self, validate=True):
            plan = super().build(validate=False)
            if self.report_enabled and self.report_paths:
                plan['dataflow']['reporting'] = {'scope': 'STORED_WARNING_RECORDS',
                    'notification_only': True, 'excluded_enrichment': self.report_details,
                    'eligibility': self.report_guards}
                import sys
                module = sys.modules[base.__module__]
                plan['coverage_review'] = module.coverage_review(plan, None)
                plan['onboarding_review'] = module.onboarding_review(plan)
            if validate:
                import sys
                sys.modules[base.__module__].validate_plan(plan, self.source)
            return plan
    return ReportBuilder


def render_dependency_sop(plan, dag_id):
    flow = plan.get('dataflow', {})
    reporting = flow.get('reporting')
    if not reporting:
        return _report_base_renderer(plan, dag_id)
    class ReportDescription(Description):
        def expression(self, value, bindings=None, depth=0):
            if value.get('op') in {'and', 'or'} and len(value.get('values', [])) == 1:
                return self.expression(value['values'][0], bindings, depth + 1)
            if value.get('op') == 'not':
                child = value['value']
                if child.get('op') in {'and', 'or'} and len(child.get('values', [])) == 1:
                    return self.expression({'op': 'not', 'value': child['values'][0]}, bindings, depth + 1)
                if child.get('op') == 'compare' and len(child['operators']) == 1:
                    opposites = {'Gt': 'LtE', 'GtE': 'Lt', 'Lt': 'GtE', 'LtE': 'Gt', 'Eq': 'NotEq', 'NotEq': 'Eq'}
                    if child['operators'][0] in opposites:
                        return self.expression({**child, 'operators': [opposites[child['operators'][0]]]}, bindings, depth + 1)
            if value.get('op') == 'index' and value.get('index') == literal(0):
                row = value['value']
                if row.get('op') == 'index' and row.get('index') == literal(0) and row['value'].get('op') == 'rows':
                    key = row['value']['check']
                    check = next((c for c in plan['diagnostics'] if c['id'] == key), None)
                    number = next((i for i, c in enumerate(plan['diagnostics'], 1) if c['id'] == key), '?')
                    if check and re.match(r'(?is)^\s*SELECT\s+COUNT\s*\(\s*\*\s*\)', check['operation']):
                        return 'count returned by step ' + str(number)
                    return 'column 1 of the first result row from step ' + str(number)
            return super().expression(value, bindings, depth)
    description = ReportDescription(flow)
    target = plan['target']
    lines = ['# INVESTIGATION SOP FOR ' + dag_id, '', 'Component ID: ' + dag_id,
        'Operating mode: INVESTIGATE_ONLY', 'Registered DATABASE target: ' + target['id'],
        '- Procedure basis: validated DAG source.', 'Assessment scope: CURRENT_STATE',
        'Investigation subject: STORED_WARNING_RECORDS', '',
        'Investigate the stored records controlling the source warning/report decision at verification time. '
        'This procedure does not establish that the Airflow report task or email delivery succeeded. '
        'A notification condition does not establish an application failure or an alert severity.']
    review = plan.get('coverage_review', {})
    if review.get('accepted'):
        lines += ['', 'Accepted limited coverage: the overall result must remain INCONCLUSIVE.',
                  '<!-- RCA_LIMITED_COVERAGE_V1:' + review['token'] + ' -->']
    if plan.get('airflow_variables'):
        lines += ['', 'Configured values used for this procedure:']
        lines.extend('- ' + item['name'] + ': ' + (json.dumps(item.get('value'), ensure_ascii=False)
                     if item.get('confirmed') else 'UNCONFIRMED') for item in plan['airflow_variables'])
    for index, check in enumerate(plan['diagnostics'], 1):
        guard = reporting['eligibility'].get(check['id'])
        if guard:
            lines += ['', 'Run step ' + str(index) + ' only if ' + description.expression(description.expanded(guard))
                      + '. Otherwise skip this supporting detail check.']
        lines += ['', str(index) + ". Run query_database on target '" + check['target_id']
                  + "' with this exact read-only query:", '', '```sql', check['operation'], '```']
    lines += ['', 'Interpret the current results:']
    for rule in flow['rules']:
        outcome = 'NO_REMEDIATION_REQUIRED' if rule['outcome'] == 'SOURCE_NO_ALERT' else rule['outcome']
        lines.append('- If ' + description.expression(description.expanded(rule['expression'])) + ': ' + outcome + '.')
    lines += ['- A notification-eligible result means stored records need review. Read the returned messages and categories; '
              'do not invent their cause, severity, or a remediation command.',
              '- A non-notification result means the current stored records do not meet the source report condition. '
              'It does not prove that the report task or email delivery is working.',
              '- Missing or invalid required measurements, failed required queries or truncated required results are '
              'INCONCLUSIVE. A COUNT(*) result must be numeric and nonnegative. A failed query is not a zero count.',
              '- Evaluate each incident group against this scope. An unrelated task exception is not assessed by warning counts.',
              '- The source queries use the database clock when each query runs. Separate checks can observe different '
              'records near a moving-window boundary; report conflicting evidence instead of claiming a single atomic snapshot.']
    if reporting['excluded_enrichment']:
        lines += ['', 'Report enrichment outside this assessment:',
                  '- Per-record enrichment and report formatting remain source context. They are not executable diagnostics '
                  'in this procedure and are not required to determine whether stored warning records meet the report condition. '
                  'Do not claim that lot matching, message parsing or report generation succeeded.']
    if plan['unknowns']:
        lines += ['', 'Review limitations:', *['- ' + item['reason'] for item in plan['unknowns']]]
    lines += ['', 'Do not send notifications, write to a database, restart services or execute other state-changing operations. '
              'No automatic remediation is authorized.']
    return '\n'.join(lines)


def evaluate_plan(plan, rows, checked_date=None):
    if plan.get('dataflow', {}).get('reporting'):
        evaluator = Evaluation(plan['dataflow'], rows, checked_date)
        for rule in plan['rules']:
            for key in rule['diagnostic_ids']:
                check = next((c for c in plan['diagnostics'] if c['id'] == key), None)
                if check and re.match(r'(?is)^\s*SELECT\s+COUNT\s*\(\s*\*\s*\)', check['operation']):
                    try:
                        result = evaluator.run({'op': 'rows', 'check': key})
                        count = list(result[0].values())[0] if isinstance(result[0], dict) else result[0][0]
                        if type(count) not in (int, float) or count < 0 or (type(count) is float and not math.isfinite(count)):
                            raise InvalidMeasurement('The required count is missing or invalid')
                    except (InvalidMeasurement, IndexError, KeyError, TypeError, ValueError) as exc:
                        return {'classification': 'INCONCLUSIVE', 'rules': [], 'error': str(exc)}
    return _report_base_evaluator(plan, rows, checked_date)
