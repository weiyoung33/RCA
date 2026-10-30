"""Read-only planning tests and independent source-calculation comparisons."""
from pathlib import Path
import sys

PROJECT=Path.cwd()/'backend'/'app'
APP=PROJECT if (PROJECT/'evidence_plan.py').is_file() else Path(__file__).resolve().parents[1]/'backend'/'app'
sys.path.insert(0,str(APP))

import copy
import datetime as dt
import json
import random
import unittest

from evidence_plan import build_plan,render_sop,validate_plan,validate_source_activation,is_read_only_select
from source_dependencies import evaluate_plan,Evaluation

SOURCE=(Path(__file__).with_name('fixtures')/'model_monitor.py.txt').read_text()
TARGET={'id':'TEST_DB','type':'DATABASE','hostname':'test.example','port':3344,'database_name':'production'}
MAPPING={'hostname':'test.example','port':3344,'database_name':'production','confirmed':True}


def plan(source=SOURCE,variables=None):
    return build_plan(source,TARGET,variables or {},{'mysql_flipchip':MAPPING})


def rows(means=(.7,),lots=(2,),yesterday=20):
    dates=[(dt.date(2026,10,24)-dt.timedelta(days=i)).isoformat() for i in range(len(means))]
    return {'check_1':[[date,.1,1.0,100+i,mean] for i,(date,mean) in enumerate(zip(dates,means))],
            'check_2':[[lot,date] for date,lot in zip(dates,lots)],'check_3':[[yesterday]]}


def source_oracle(data,minimum=2,window=7,threshold=.8):
    """Independent calculation of the posted source's data-selection semantics."""
    summary=data['check_1']
    selected_lots=data['check_2'][:len(summary)+1]
    lookup={row[1]:row[0] for row in selected_lots}
    filtered=[row for row in summary if lookup.get(row[0],0)>=minimum][:window]
    average=sum(row[4] for row in filtered)/len(filtered) if filtered else None
    if data['check_3'][0][0]>0 and average is not None:
        return 'MANUAL_REVIEW_REQUIRED' if average<=threshold else 'NO_REMEDIATION_REQUIRED'
    return 'INCONCLUSIVE'


class DependencyTests(unittest.TestCase):
    def test_reporting_helpers_and_callbacks_do_not_hide_the_monitoring_data_flow(self):
        source=(Path(__file__).with_name('fixtures')/'model_monitor_with_reporting.py.txt').read_text()
        result=plan(source)
        self.assertEqual(result['unknowns'],[])
        self.assertEqual(result['confirmation_questions'],[])
        self.assertEqual(len(result['diagnostics']),3)
        self.assertEqual(evaluate_plan(result,rows((.9,)))['classification'],'NO_REMEDIATION_REQUIRED')

    def test_all_three_queries_are_resolved_without_runtime_value_questions(self):
        result=plan()
        self.assertEqual(len(result['diagnostics']),3)
        self.assertEqual(result['unknowns'],[])
        self.assertEqual(result['confirmation_questions'],[])
        self.assertEqual(len(result['rules']),2)
        self.assertTrue(result['dataflow']['complete'])

    def test_constants_and_irrelevant_airflow_variables_are_distinguished(self):
        result=plan()
        values={v['name']:v['value'] for v in result['thresholds']}
        self.assertEqual(values['alert_probability'],.8)
        self.assertEqual(values['min_lot_processed'],2)
        self.assertFalse(result['airflow_variables'])
        self.assertIn('flipchip_proj_mlops_email_list',[v['name'] for v in result['ignored_airflow_variables']])

    def test_dependent_limit_retains_its_binding_and_all_queries_are_read_only(self):
        result=plan()
        check=result['diagnostics'][1]
        self.assertEqual(check['dependency_ids'],['check_1'])
        self.assertIsNotNone(check['result_limit'])
        self.assertNotIn('LIMIT',check['operation'])
        self.assertTrue(all(is_read_only_select(c['operation']) for c in result['diagnostics']))

    def test_relative_date_uses_database_calendar_and_has_no_fixed_date(self):
        result=plan()
        query=result['diagnostics'][2]['operation']
        self.assertIn('CURRENT_DATE() - INTERVAL 1 DAY',query)
        self.assertNotIn('2026-',query)
        self.assertIn('Airflow host date',render_sop(result,'flipchip_monitor_ml'))

    def test_threshold_is_inclusive(self):
        self.assertEqual(evaluate_plan(plan(),rows((.8,)))['classification'],'MANUAL_REVIEW_REQUIRED')
        self.assertEqual(evaluate_plan(plan(),rows((.80001,)))['classification'],'NO_REMEDIATION_REQUIRED')

    def test_one_qualifying_day_is_allowed_by_this_source(self):
        self.assertEqual(evaluate_plan(plan(),rows((.9,)))['classification'],'NO_REMEDIATION_REQUIRED')

    def test_no_production_does_not_invent_model_health(self):
        self.assertEqual(evaluate_plan(plan(),rows((.9,),yesterday=0))['classification'],'INCONCLUSIVE')

    def test_no_qualifying_days_does_not_divide_by_zero(self):
        result=evaluate_plan(plan(),rows((.9,),(1,)))
        self.assertEqual(result['classification'],'INCONCLUSIVE')
        self.assertFalse(result['error'])

    def test_no_summary_rows_is_inconclusive(self):
        self.assertEqual(evaluate_plan(plan(),{'check_1':[],'check_2':[],'check_3':[[0]]})['classification'],'INCONCLUSIVE')

    def test_missing_lot_date_uses_exact_source_default_zero(self):
        data=rows((.9,.1),(2,2))
        data['check_2']=data['check_2'][:1]
        self.assertEqual(evaluate_plan(plan(),data)['classification'],'NO_REMEDIATION_REQUIRED')

    def test_mean_is_unweighted_across_daily_averages(self):
        data=rows((.7,.9),(2,2))
        data['check_1'][1][3]=1000000
        self.assertEqual(evaluate_plan(plan(),data)['classification'],'MANUAL_REVIEW_REQUIRED')

    def test_latest_seven_qualifying_days_are_selected_before_averaging(self):
        data=rows((.1,)+(.9,)*7+(.1,)*3,(1,)+(2,)*10)
        self.assertEqual(evaluate_plan(plan(),data)['classification'],'NO_REMEDIATION_REQUIRED')

    def test_runtime_limit_applies_before_date_lookup(self):
        data=rows((.9,.1),(2,2))
        data['check_2']=[[2,'2099-01-01'],[2,'2099-01-02'],data['check_2'][0],data['check_2'][1]]
        # Source LIMIT = two summary rows + one. The older low-mean day's
        # lot count is outside that limit, so that day must remain excluded.
        self.assertEqual(evaluate_plan(plan(),data)['classification'],'NO_REMEDIATION_REQUIRED')

    def test_null_average_is_not_silently_dropped(self):
        self.assertEqual(evaluate_plan(plan(),rows((None,)))['classification'],'INCONCLUSIVE')

    def test_nonfinite_average_cannot_become_a_healthy_result(self):
        self.assertEqual(evaluate_plan(plan(),rows((float('nan'),)))['classification'],'INCONCLUSIVE')

    def test_dictionary_shaped_tool_rows_preserve_source_column_order(self):
        data=rows((.9,))
        data['check_1']=[dict(zip(('day','minimum','maximum','images','average'),data['check_1'][0]))]
        data['check_2']=[dict(zip(('lots','day'),data['check_2'][0]))]
        data['check_3']=[{'observations':20}]
        self.assertEqual(evaluate_plan(plan(),data)['classification'],'NO_REMEDIATION_REQUIRED')

    def test_truncated_results_are_not_complete_evidence(self):
        data=rows((.9,))
        data['check_2']={'status':'SUCCESS','rows':data['check_2'],'rows_truncated':True}
        self.assertEqual(evaluate_plan(plan(),data)['classification'],'INCONCLUSIVE')

    def test_missing_check_is_inconclusive(self):
        data=rows((.9,));del data['check_2']
        self.assertEqual(evaluate_plan(plan(),data)['classification'],'INCONCLUSIVE')

    def test_names_and_thresholds_are_not_hardcoded(self):
        source=SOURCE.replace('alert_probability=0.8','alert_probability=0.95').replace('min_lot_processed=2','min_lot_processed=3').replace('filtered_days[:7]','filtered_days[:3]')
        for old,new in [('nb_records','how_many'),('summary_records','readings'),('merged_records','joined_rows'),('average_7_days','metric'),('lot_by_date','lookup'),('flipchip_monitor_ml','future_monitor')]: source=source.replace(old,new)
        result=plan(source)
        data=rows((.96,.96,.96,.1),(3,3,3,3))
        self.assertEqual(result['unknowns'],[])
        self.assertEqual(evaluate_plan(result,data)['classification'],'NO_REMEDIATION_REQUIRED')

    def test_randomized_inputs_match_an_independent_source_oracle(self):
        result=plan()
        generator=random.Random(7281)
        for _ in range(100):
            count=generator.randrange(0,31)
            data=rows(tuple(generator.choice((.2,.7,.8,.9,.99)) for _ in range(count)),tuple(generator.randrange(5) for _ in range(count)),generator.choice((0,20)))
            if data['check_2']: generator.shuffle(data['check_2'])
            self.assertEqual(evaluate_plan(result,data)['classification'],source_oracle(data))

    def test_positional_date_parameter_is_resolved(self):
        source=SOURCE.replace('check_yesterday_qry=f"SELECT COUNT(*) FROM t_inference WHERE DATE(date) = \'{yesterday}\'"','check_yesterday_qry="SELECT COUNT(*) FROM t_inference WHERE DATE(date) = %s"').replace('db_cursor_proj.execute(check_yesterday_qry)','db_cursor_proj.execute(check_yesterday_qry,(yesterday,))')
        result=plan(source)
        self.assertEqual(result['unknowns'],[])
        self.assertNotIn('%s',result['diagnostics'][2]['operation'])

    def test_named_date_parameter_is_resolved(self):
        source=SOURCE.replace('check_yesterday_qry=f"SELECT COUNT(*) FROM t_inference WHERE DATE(date) = \'{yesterday}\'"','check_yesterday_qry="SELECT COUNT(*) FROM t_inference WHERE DATE(date) = %(when)s"').replace('db_cursor_proj.execute(check_yesterday_qry)',"db_cursor_proj.execute(check_yesterday_qry,{'when':yesterday})")
        self.assertFalse(plan(source)['unknowns'])

    def test_format_construction_is_resolved(self):
        source=SOURCE.replace('check_yesterday_qry=f"SELECT COUNT(*) FROM t_inference WHERE DATE(date) = \'{yesterday}\'"','check_yesterday_qry="SELECT COUNT(*) FROM t_inference WHERE DATE(date) = \'{}\'".format(yesterday)')
        self.assertFalse(plan(source)['unknowns'])

    def test_import_aliases_for_date_and_duration_are_supported(self):
        source=SOURCE.replace('from datetime import datetime, timedelta, date','from datetime import datetime, timedelta as duration, date as calendar').replace('date.today()-timedelta(days=1)','calendar.today()-duration(days=1)')
        self.assertFalse(plan(source)['unknowns'])

    def test_confirmed_airflow_threshold_is_used_without_reasking(self):
        source=SOURCE.replace('alert_probability=0.8',"alert_probability=float(Variable.get('probability_limit'))")
        result=plan(source,{'probability_limit':'0.9'})
        self.assertEqual(result['confirmation_questions'],[])
        self.assertEqual(evaluate_plan(result,rows((.85,)))['classification'],'MANUAL_REVIEW_REQUIRED')

    def test_simple_pure_helper_can_supply_the_mean(self):
        source=SOURCE.replace('@task\ndef summarize_t_inference', 'def daily_mean(items):\n    return sum(x[4] for x in items)/len(items)\n\n@task\ndef summarize_t_inference').replace('sum(record[4] for record in last_7_days)/num_days','daily_mean(last_7_days)')
        result=plan(source)
        self.assertFalse(result['unknowns'])
        self.assertEqual(evaluate_plan(result,rows((.85,)))['classification'],'NO_REMEDIATION_REQUIRED')

    def test_unsupported_helper_does_not_become_a_supported_health_branch(self):
        source=SOURCE.replace('sum(record[4] for record in last_7_days)/num_days','unknown_transform(last_7_days)')
        result=plan(source)
        self.assertTrue(result['unknowns'])
        self.assertFalse(result['dataflow']['complete'])

    def test_unordered_runtime_limit_is_not_silently_changed(self):
        result=plan(SOURCE.replace('ORDER BY DATE(LoadingTime) DESC LIMIT','LIMIT'))
        self.assertTrue(result['unknowns'])

    def test_partial_date_literal_is_not_rewritten_as_a_different_query(self):
        result=plan(SOURCE.replace("'{yesterday}'","'prefix{yesterday}suffix'"))
        self.assertTrue(result['unknowns'])

    def test_source_is_not_executed_during_planning(self):
        self.assertEqual(len(plan("raise RuntimeError('never run')\n"+SOURCE)['diagnostics']),3)

    def test_calculation_tampering_is_rejected(self):
        result=plan();result['dataflow']['rules'][0]['expression']={'op':'literal','value':True}
        with self.assertRaises(ValueError): validate_plan(result,SOURCE)

    def test_normalized_query_tampering_is_rejected(self):
        result=plan();result['diagnostics'][2]['operation']='SELECT COUNT(*) FROM unrelated_table'
        with self.assertRaises(ValueError): validate_plan(result,SOURCE)

    def test_activation_rebuilds_the_dependency_plan(self):
        result=plan()
        registration={'mode':'EXISTING_DATABASE','database_target_id':'TEST_DB'}
        review={'dag_source_code':SOURCE,'investigation_read_only':True,'dag_id':'flipchip_monitor_ml',
                'exception_types':['AirflowAlertException'],'target_registration':registration,
                'airflow_variable_values':{},'connection_mappings':{'mysql_flipchip':MAPPING}}
        draft={'operating_mode':'INVESTIGATE_ONLY','target_registration':registration,'dag':{
            'dag_id':'flipchip_monitor_ml','exception_types':['AirflowAlertException'],'investigation_sop':render_sop(result,'flipchip_monitor_ml')}}
        context={'ssh_targets':[],'database_targets':[{'database_target_id':'TEST_DB','hostname':'test.example','database_port':3344,'database_name':'production'}]}
        self.assertIsNotNone(validate_source_activation(review,draft,context))
        draft['dag']['investigation_sop']=draft['dag']['investigation_sop'].replace('≤ 0.8','≤ 0.9')
        with self.assertRaises(ValueError): validate_source_activation(review,draft,context)

    def test_sop_is_readable_and_has_no_unresolved_python_sql(self):
        sop=render_sop(plan(),'flipchip_monitor_ml')
        self.assertNotIn('{nb_records',sop)
        self.assertNotIn('{yesterday}',sop)
        self.assertNotIn('vstdout',sop)
        self.assertIn('first 7',sop)
        self.assertIn('≥ 2',sop)
        self.assertIn('≤ 0.8',sop)
        self.assertEqual(sop.count('- average 7 days:'),1)


if __name__=='__main__': unittest.main()
