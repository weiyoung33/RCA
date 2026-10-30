import importlib.util
import json
from pathlib import Path
import sys
import unittest

PATH=Path(__file__).resolve().parents[1]/'backend'/'app'/'action_candidates.py'
spec=importlib.util.spec_from_file_location('action_candidates_test',PATH)
module=importlib.util.module_from_spec(spec)
sys.modules[spec.name]=module
spec.loader.exec_module(module)
extract=module.extract_action_candidates

WATCHDOG='''
from airflow.models import Variable
RAM_threshold = 50
def monitor():
    hook = SSHHook(ssh_conn_id='ssh_project')
    client = hook.get_conn()
    command = 'pgrep -f --count ' + Variable.get('watchdog_path')
    _, out, err = client.exec_command(command)
    count = int(out.readlines()[0].rstrip())
    if count == 1:
        command = '/apps/monitor/bin/python -c "import psutil; print(psutil.cpu_percent(interval=1)); print(psutil.virtual_memory().percent)"'
        _, out, err = client.exec_command(command)
        lines = out.readlines()
        memory = 0
        if len(lines) > 0:
            cpu = lines[0].rstrip()
            memory = lines[1].rstrip()
        if float(memory) >= RAM_threshold:
            command = 'pgrep -f ' + Variable.get('watchdog_path')
            _, out, err = client.exec_command(command)
            text = out.read().decode().strip()
            pids = [p for p in text.split() if p]
            if len(pids) != 1:
                raise Exception('ambiguous')
            else:
                pid = pids[0]
                kill_command = f'kill {pid}'
                _, out, err = client.exec_command(kill_command)
                trigger = TriggerDagRunOperator(trigger_dag_id='execute_worker', wait_for_completion=False)
                trigger.execute(context=kwargs)
with DAG(dag_id='new_project_monitor'):
    monitor()
'''


class CandidateTests(unittest.TestCase):
    def test_supplied_flow_maps_runtime_pid_and_retains_restart_dependency(self):
        result=extract(WATCHDOG,{'watchdog_path':'"/apps/project/worker.py"'})
        self.assertEqual(len(result['candidates']),1)
        candidate=result['candidates'][0]
        self.assertEqual(candidate['prefill']['operation'],'RESTART_SCRIPT')
        self.assertEqual(candidate['prefill']['process_path'],'/apps/project/worker.py')
        self.assertIn('command',candidate['missing_fields'])
        self.assertIn('execute_worker',' '.join(candidate['notes']))
        self.assertIn('memory_percent',candidate['prefill']['health_command'])
        self.assertIn('50',candidate['prefill']['health_command'])
        self.assertEqual(candidate['source_connections'],['ssh_project'])
        json.dumps(result)

    def test_missing_source_variable_is_asked_once(self):
        result=extract(WATCHDOG)
        self.assertEqual([v['key'] for v in result['required_variables']],['watchdog_path'])
        self.assertNotIn('kill {',result['candidates'][0]['prefill'].get('command',''))

    def test_fixed_service_restart_is_prefilled_with_status_check(self):
        source="unit='another-worker.service'\nclient.exec_command(f'systemctl restart {unit}')"
        candidate=extract(source)['candidates'][0]
        self.assertEqual(candidate['prefill']['command'],'systemctl restart another-worker.service')
        self.assertIn('is-active',candidate['prefill']['health_command'])
        self.assertEqual(candidate['missing_fields'],[])

    def test_trim_uses_source_slice_and_variable_names_do_not_matter(self):
        source='''
_, a, b = client.exec_command('pgrep -f /other/project/collect.py')
workers = a.read().decode().split()
for item in workers[2:]:
    client.exec_command(f'kill -TERM {item}')
'''
        candidate=extract(source)['candidates'][0]
        self.assertEqual(candidate['prefill']['operation'],'TRIM_PROCESSES')
        self.assertEqual(candidate['prefill']['expected_count'],2)

    def test_disabled_code_and_plain_diagnostics_are_not_actions(self):
        source="enabled=False\nif enabled:\n client.exec_command('kill 123')\nclient.exec_command('pgrep -c -f worker.py')\n# client.exec_command('reboot')"
        self.assertEqual(extract(source)['candidates'],[])

    def test_known_start_command_is_copied_without_guessing(self):
        source='''
_, out, _ = client.exec_command('pgrep -f /apps/another.py')
pids = out.read().decode().split()
for pid in pids:
    client.exec_command(f'kill {pid}')
client.exec_command('/apps/another/start.sh')
'''
        candidates=extract(source)['candidates']
        self.assertEqual(len(candidates),1)
        self.assertEqual(candidates[0]['prefill']['operation'],'RESTART_SCRIPT')
        self.assertEqual(candidates[0]['prefill']['command'],'/apps/another/start.sh')

    def test_unrelated_notification_variables_are_not_requested(self):
        result=extract("email=Variable.get('email_list')\nclient.exec_command('systemctl restart worker')")
        self.assertEqual(result['required_variables'],[])

    def test_loop_actions_have_distinct_ids(self):
        result=extract("for unit in ['one.service','two.service']:\n client.exec_command(f'systemctl restart {unit}')")
        self.assertEqual(len(result['candidates']),2)
        self.assertEqual(len({c['id'] for c in result['candidates']}),2)

    def test_percent_interpolation_keeps_runtime_pid_symbolic(self):
        source="_, out, _=client.exec_command('pgrep -f /apps/worker.py')\npid=out.read().decode().split()[0]\nclient.exec_command('kill %s' % pid)"
        result=extract(source)['candidates'][0]
        self.assertEqual(result['prefill']['operation'],'STOP_PROCESSES')
        self.assertEqual(result['prefill']['process_path'],'/apps/worker.py')
        self.assertEqual(result['prefill']['command'],'')

    def test_aliased_variable_and_config_dictionary_are_resolved(self):
        source="from airflow.models import Variable as V\nconfig={'cmd':'systemctl restart '+V.get('unit')}\nclient.exec_command(config['cmd'])"
        result=extract(source,{'unit':'"future-dag-worker"'})
        self.assertEqual(result['candidates'][0]['prefill']['command'],'systemctl restart future-dag-worker')

    def test_source_start_command_reuses_count_condition(self):
        source="_, out, _=client.exec_command('pgrep -c -f /apps/new/main.py')\nn=int(out.readlines()[0])\nif n==0:\n client.exec_command('/apps/venv/bin/python /apps/new/main.py')"
        result=extract(source)['candidates'][0]
        self.assertEqual(result['missing_fields'],[])
        self.assertIn('/apps/new/main.py',result['prefill']['health_command'])

    def test_constant_false_comparison_is_not_active_source(self):
        result=extract("enabled=0\nif enabled==1:\n client.exec_command('systemctl restart disabled')")
        self.assertEqual(result['candidates'],[])

    def test_unrelated_branch_does_not_supply_a_restart(self):
        source="_,out,_=client.exec_command('pgrep -f /apps/one.py')\npid=out.read().decode().split()[0]\nif flag:\n client.exec_command(f'kill {pid}')\nelse:\n client.exec_command('/apps/unrelated/start.sh')"
        result=extract(source)['candidates'][0]
        self.assertEqual(result['prefill']['operation'],'STOP_PROCESSES')

    def test_unused_helper_and_sql_writes_are_not_executable_candidates(self):
        result=extract("def unused():\n client.exec_command('reboot')\ncursor.execute('UPDATE audit SET status=1')")
        self.assertEqual(result['candidates'],[])

    def test_source_code_is_never_executed(self):
        source="raise RuntimeError('must never run')\nclient.exec_command('systemctl restart worker')"
        self.assertEqual(len(extract(source)['candidates']),1)

    def test_entire_command_from_variable_is_resolved_without_name_guessing(self):
        source="cmd=Variable.get('remote_operation')\nclient.exec_command(cmd)"
        before=extract(source)
        self.assertEqual(before['required_variables'][0]['key'],'remote_operation')
        after=extract(source,{'remote_operation':'"systemctl restart fresh-worker"'})
        self.assertEqual(after['candidates'][0]['prefill']['command'],'systemctl restart fresh-worker')

    def test_bad_source_returns_an_actionable_error(self):
        with self.assertRaisesRegex(ValueError,'Invalid Python near source line'):
            extract('if :')

    def test_conditional_command_assignments_remain_distinct(self):
        source="if flag:\n command='systemctl restart one'\nelse:\n command='systemctl restart two'\nclient.exec_command(command)"
        result=extract(source)
        self.assertEqual({c['prefill']['command'] for c in result['candidates']},{'systemctl restart one','systemctl restart two'})

    def test_variable_used_only_in_source_condition_is_requested(self):
        result=extract("enabled=Variable.get('repair_enabled')\nif enabled=='yes':\n client.exec_command('systemctl restart worker')")
        self.assertEqual([v['key'] for v in result['required_variables']], ['repair_enabled'])
        self.assertIn('does not reproduce', ' '.join(result['candidates'][0]['notes']))

    def test_pid_loop_preserves_multi_process_scope(self):
        source="_, out, _=client.exec_command('pgrep -f /apps/worker.py')\npids=out.read().decode().split()\nfor pid in pids:\n client.exec_command(f'kill {pid}')"
        result=extract(source)['candidates'][0]['prefill']
        self.assertEqual(result['operation'], 'STOP_PROCESSES')
        self.assertGreater(result['max_matches'], 1)


if __name__=='__main__': unittest.main()
