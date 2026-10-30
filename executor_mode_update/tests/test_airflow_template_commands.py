"""General Airflow Variable template support plus the reported startup DAG."""
import json
from pathlib import Path
import unittest

from test_action_candidates import WATCHDOG, extract, module

SOURCE=(Path(__file__).with_name('fixtures')/'flipchip_execute_linux_watchdog.py.txt').read_text()
VALUES={
    'flipchip_proj_pythonvenvpath':'"/test/venv/bin/python"',
    'flipchip_proj_scriptpath':'"/test/project/"',
    'flipchip_proj_linux_watchdog':'"worker.py"',
}
EXPECTED='nohup /test/venv/bin/python /test/project/worker.py >/dev/null 2>&1 &'
MONITOR=WATCHDOG.replace('watchdog_path','flipchip_proj_linux_watchdog').replace('execute_worker','flipchip_execute_linux_watchdog').replace('ssh_project','ssh_flipchip')


class TemplateCommandTests(unittest.TestCase):
    def test_reported_dag_requests_only_its_three_startup_values(self):
        result=extract(SOURCE)
        self.assertEqual(len(result['candidates']),1)
        self.assertEqual({v['key'] for v in result['required_variables']},set(VALUES))
        self.assertEqual(result['candidates'][0]['prefill']['command'],'')
        self.assertEqual(result['candidates'][0]['source_connections'],['ssh_flipchip'])

    def test_reported_dag_renders_the_exact_command_after_values_are_supplied(self):
        candidate=extract(SOURCE,VALUES)['candidates'][0]
        self.assertEqual(candidate['prefill']['command'],EXPECTED)
        self.assertNotIn('{{',candidate['prefill']['command'])

    def test_reported_dag_links_to_monitor_and_fills_the_full_process_path(self):
        result=extract(MONITOR,VALUES,related_dag_sources={'flipchip_execute_linux_watchdog':SOURCE})
        candidate=result['candidates'][0]
        self.assertEqual(result['required_variables'],[])
        self.assertEqual(candidate['prefill']['command'],EXPECTED)
        self.assertEqual(candidate['prefill']['process_path'],'/test/project/worker.py')
        self.assertNotIn('command',candidate['missing_fields'])
        self.assertNotIn('process_path',candidate['missing_fields'])
        self.assertIn('memory_percent',json.dumps(candidate['prefill']['source_health_policy']))

    def test_missing_values_remain_a_startup_choice_instead_of_no_supported_command(self):
        result=extract(MONITOR,related_dag_sources={'flipchip_execute_linux_watchdog':SOURCE})
        self.assertEqual({v['key'] for v in result['required_variables']},set(VALUES))
        self.assertEqual(len(result['candidates'][0]['startup_options']),1)
        self.assertFalse(result['candidates'][0]['startup_options'][0]['command'])
        self.assertNotIn('No supported startup command',' '.join(result['related_source_results']['flipchip_execute_linux_watchdog']['notes']))

    def test_partial_values_ask_only_for_the_remaining_key(self):
        values={key:value for key,value in VALUES.items() if key!='flipchip_proj_scriptpath'}
        result=extract(SOURCE,values)
        self.assertEqual([v['key'] for v in result['required_variables']],['flipchip_proj_scriptpath'])
        self.assertEqual(result['candidates'][0]['prefill']['command'],'')

    def test_arbitrary_variable_names_and_bracket_notation_work(self):
        source="client.exec_command(\"nohup {{var.value['interpreter.path']}} {{ var.value.another_script }} &\")"
        result=extract(source,{'interpreter.path':'"/new/bin/python3"','another_script':'"/new/task.py"'})
        self.assertEqual(result['candidates'][0]['prefill']['command'],'nohup /new/bin/python3 /new/task.py &')

    def test_unknown_template_calls_are_not_executed_or_copied_as_commands(self):
        source='client.exec_command(\'nohup {{ __import__("os").system("must-never-run") }} &\')'
        candidate=extract(source)['candidates'][0]
        self.assertEqual(candidate['prefill']['command'],'')
        self.assertTrue(candidate['template_issues'])

    def test_templates_in_control_blocks_are_explicitly_unresolved(self):
        source='client.exec_command("{% if params.start %} /apps/start.sh {% endif %}")'
        candidate=extract(source)['candidates'][0]
        self.assertEqual(candidate['prefill']['command'],'')
        self.assertTrue(candidate['template_issues'])

    def test_path_separator_is_preserved_instead_of_invented(self):
        values={**VALUES,'flipchip_proj_scriptpath':'"/test/project"'}
        command=extract(SOURCE,values)['candidates'][0]['prefill']['command']
        self.assertIn('/test/projectworker.py',command)
        self.assertNotIn('/test/project/worker.py',command)

    def test_missing_template_values_propagate_through_pid_discovery(self):
        source="_,out,_=client.exec_command('pgrep -f {{var.value.process_path}}')\npid=out.read().decode().split()[0]\nclient.exec_command(f'kill {pid}')"
        result=extract(source)
        self.assertIn('process_path',[v['key'] for v in result['required_variables']])
        self.assertEqual(result['candidates'][0]['prefill']['operation'],'STOP_PROCESSES')


if __name__=='__main__': unittest.main()
