from pathlib import Path
import ast
import __future__
import sys
import types
import unittest

from test_source_dependencies import APP,SOURCE,TARGET,MAPPING
from evidence_plan import build_plan,render_sop,target_from_registration
from dag_source_analysis import analyze_dag_source


class DependencyRouteTests(unittest.TestCase):
    @unittest.skipUnless((APP/'onboarding_agent.py').is_file(),'Run after installation in the application project root')
    def test_deterministic_source_draft_does_not_call_model_or_database(self):
        tree=ast.parse((APP/'onboarding_agent.py').read_text(encoding='utf-8-sig'))
        function=next(v for v in tree.body if isinstance(v,ast.FunctionDef) and v.name=='_call_source_sop')
        def model_value(value): return types.SimpleNamespace(model_dump=lambda **kwargs:value)
        structured=types.SimpleNamespace(dag_source_code=SOURCE,dag_id='flipchip_monitor_ml',exception_types=['AirflowAlertException'],
            target_registration=model_value({'mode':'EXISTING_DATABASE','database_target_id':'TEST_DB'}),
            connection_mappings={'mysql_flipchip':model_value(MAPPING)},airflow_variable_values={},external_script_policy='EXCLUDE',limited_coverage_acknowledgement=None)
        class Response:
            @classmethod
            def model_validate(cls,value): return value
        def forbidden(*args,**kwargs): raise AssertionError('No model or database call is needed to generate this plan')
        namespace={'analyze_dag_source':analyze_dag_source,'target_from_registration':target_from_registration,
                   'build_plan':build_plan,'render_sop':render_sop,'OnboardingAssistantResponse':Response,
                   '_post_llm':forbidden,'database_cursor':forbidden}
        exec(compile(ast.Module(body=[function],type_ignores=[]),'source_route.py','exec',flags=__future__.annotations.compiler_flag),namespace)
        context={'ssh_targets':[],'database_targets':[{'database_target_id':'TEST_DB','hostname':'test.example','database_port':3344,'database_name':'production'}]}
        result=namespace['_call_source_sop'](types.SimpleNamespace(structured_input=structured),context)
        self.assertTrue(result['ready_for_review'])
        self.assertEqual(result['validation_issues'],[])
        self.assertEqual(len(result['source_plan']['diagnostics']),3)
        self.assertEqual(result['draft']['target_registration']['database_target_id'],'TEST_DB')


if __name__=='__main__': unittest.main()
