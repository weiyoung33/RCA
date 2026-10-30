"""Source association and automatic prefill tests. No source or command runs."""
import json
import unittest

from test_action_candidates import WATCHDOG, extract


def restart_source(command="nohup /apps/project/bin/python /apps/project/worker.py >/tmp/worker.log 2>&1 &", connection='ssh_project', dag='execute_worker'):
    return ("from airflow.models import DAG, Variable\n"
            "from airflow.providers.ssh.operators.ssh import SSHOperator\n"
            f"dag_name={dag!r}\n"
            "with DAG(dag_id=dag_name):\n"
            f"    launch=SSHOperator(task_id='launch', ssh_conn_id={connection!r}, command={command!r})\n")


class LinkedStartupTests(unittest.TestCase):
    def get(self,source=None,variables=None,main=WATCHDOG):
        return extract(main,variables or {'watchdog_path':json.dumps('/apps/project/worker.py')},
                       related_dag_sources={'execute_worker':source if source is not None else restart_source()})

    def test_source_launch_is_prefilled_with_provenance_and_original_policy(self):
        result=self.get()
        candidate=result['candidates'][0]
        self.assertIn('nohup /apps/project/bin/python',candidate['prefill']['command'])
        self.assertNotIn('command',candidate['missing_fields'])
        self.assertEqual(candidate['startup_source']['dag_id'],'execute_worker')
        self.assertEqual(candidate['startup_source']['source_connections'],['ssh_project'])
        self.assertIn('memory_percent',candidate['prefill']['health_command'])
        self.assertEqual(candidate['prefill']['source_health_policy']['unresolved'],False)
        json.dumps(result)

    def test_matching_basename_uses_explicit_startup_path(self):
        candidate=self.get(variables={'watchdog_path':json.dumps('worker.py')})['candidates'][0]
        self.assertEqual(candidate['prefill']['process_path'],'/apps/project/worker.py')
        self.assertNotIn('process_path',candidate['missing_fields'])
        self.assertIn('memory_percent',json.dumps(candidate['prefill']['source_health_policy']))

    def test_unset_variable_is_not_invented_from_a_launch_path(self):
        result=self.get(variables={'unrelated':'"value"'})
        candidate=result['candidates'][0]
        self.assertEqual(candidate['prefill']['process_path'],'')
        self.assertIn('watchdog_path',[v['key'] for v in result['required_variables']])

    def test_related_variables_reuse_confirmed_values_and_ask_only_missing(self):
        source=restart_source().replace("command='nohup /apps/project/bin/python /apps/project/worker.py >/tmp/worker.log 2>&1 &'","command=Variable.get('worker_start')")
        missing=self.get(source)
        self.assertIn('worker_start',[v['key'] for v in missing['required_variables']])
        supplied=self.get(source,{'watchdog_path':'"/apps/project/worker.py"','worker_start':'"/apps/project/launch.sh"'})
        self.assertEqual(supplied['candidates'][0]['prefill']['command'],'/apps/project/launch.sh')

    def test_wrong_dag_source_explains_the_mismatch_without_dropping_main_action(self):
        result=self.get(restart_source(dag='another_project'))
        self.assertEqual(len(result['candidates']),1)
        self.assertIn('another_project',result['related_source_results']['execute_worker']['error'])
        self.assertEqual(result['candidates'][0]['prefill']['command'],'')

    def test_invalid_related_source_leaves_main_action_available(self):
        result=self.get('if :')
        self.assertIn('Invalid Python',result['related_source_results']['execute_worker']['error'])
        self.assertEqual(len(result['candidates']),1)

    def test_multiple_startups_require_a_choice_and_retain_exact_text(self):
        source=restart_source()+"    other=SSHOperator(task_id='other',ssh_conn_id='ssh_project',command='/apps/project/alternate.sh')\n"
        candidate=self.get(source)['candidates'][0]
        self.assertEqual(len(candidate['startup_options']),2)
        self.assertEqual(candidate['prefill']['command'],'')
        self.assertEqual(candidate['startup_options'][1]['command'],'/apps/project/alternate.sh')

    def test_different_connection_is_a_review_choice_not_an_automatic_rebinding(self):
        candidate=self.get(restart_source(connection='ssh_other_host'))['candidates'][0]
        self.assertEqual(candidate['prefill']['command'],'')
        self.assertIn('different Airflow connection',' '.join(candidate['startup_options'][0]['notes']))

    def test_airflow_worker_command_is_not_automatically_copied_to_ssh(self):
        source="with DAG(dag_id='execute_worker'):\n    launch=BashOperator(task_id='launch',bash_command='/apps/project/launch.sh')"
        candidate=self.get(source)['candidates'][0]
        self.assertEqual(candidate['prefill']['command'],'')
        self.assertIn('Airflow worker',' '.join(candidate['startup_options'][0]['notes']))

    def test_unrelated_supplied_source_is_ignored(self):
        result=extract(WATCHDOG,{'watchdog_path':'"/apps/project/worker.py"'},related_dag_sources={'other_dag':restart_source()})
        self.assertEqual(result['related_source_results'],{})
        self.assertEqual(result['candidates'][0]['prefill']['command'],'')

    def test_different_startup_script_is_visible_but_not_auto_selected(self):
        candidate=self.get(restart_source(command='/apps/python /apps/project/other.py'))['candidates'][0]
        self.assertEqual(candidate['prefill']['command'],'')
        self.assertIn('differs from the monitored process',' '.join(candidate['startup_options'][0]['notes']))

    def test_related_source_is_never_imported_or_executed(self):
        candidate=self.get("raise AssertionError('must not run')\n"+restart_source())['candidates'][0]
        self.assertTrue(candidate['prefill']['command'])

    def test_conditional_startup_is_offered_for_explicit_review(self):
        source="with DAG(dag_id='execute_worker'):\n    if readiness_flag:\n        launch=SSHOperator(task_id='launch',ssh_conn_id='ssh_project',command='/apps/project/start.sh')"
        candidate=self.get(source)['candidates'][0]
        self.assertEqual(candidate['prefill']['command'],'')
        self.assertTrue(candidate['startup_options'][0]['conditions'])

    def test_human_conditions_preserve_the_separate_pid_confirmation(self):
        candidate=self.get()['candidates'][0]
        self.assertIn('Exactly one matching process is running',candidate['conditions'])
        self.assertIn('Server RAM usage is at least 50%',candidate['conditions'])
        self.assertIn('PID discovery confirms exactly one match',candidate['conditions'])
        self.assertNotIn('not (','; '.join(candidate['conditions']))


if __name__=='__main__': unittest.main()
