from __future__ import annotations

from typing import Any, Optional


TEST_CASES: tuple[dict[str, Any], ...] = (
    {
        "test_case_id": "error_logs_warning",
        "title": "Grouped error-log warnings",
        "description": (
            "Creates two duplicate pipeline warnings and one distinct Windows "
            "log parsing error in the same batch."
        ),
        "batch_master": {
            "site_code": "MALTA",
            "proj_name": "FLIPCHIP",
            "dag_id": "flipchip_monitor_error_logs",
            "batch_start_date": "2026-09-04 17:20:00",
            "min_severity": 1,
            "alert_status": "OPEN",
        },
        "batch_details": (
            {
                "category": "DATA_PIPELINE",
                "severity": 1,
                "message": "WARNING: ERROR Log detected",
                "exception_type": "AirflowAlertException",
                "status": "FAILED",
            },
            {
                "category": "DATA_PIPELINE",
                "severity": 1,
                "message": "WARNING: ERROR Log detected",
                "exception_type": "AirflowAlertException",
                "status": "FAILED",
            },
            {
                "category": "WINDOWS_LOGS",
                "severity": 3,
                "message": "Error occured in parsing Windows Logs",
                "exception_type": "Exception",
                "status": "FAILED",
            },
        ),
        "expected_distinct_error_count": 2,
    },
    {
        "test_case_id": "gunicorn_missing",
        "title": "Gunicorn failure with secondary Python error",
        "description": (
            "Creates duplicate missing-process alerts and a distinct "
            "UnboundLocalError in the same Flask monitoring batch."
        ),
        "batch_master": {
            "site_code": "MALTA",
            "proj_name": "FLIPCHIP",
            "dag_id": "flipchip_monitor_flask_app_pll",
            "batch_start_date": "2026-09-07 16:20:00",
            "min_severity": 3,
            "alert_status": "OPEN",
        },
        "batch_details": (
            {
                "category": "APPLICATION_PROCESS",
                "severity": 3,
                "message": "0 instances of gunicorn are running. Please check.",
                "exception_type": "AirflowAlertException",
                "status": "FAILED",
            },
            {
                "category": "APPLICATION_PROCESS",
                "severity": 3,
                "message": "0 instances of gunicorn are running. Please check.",
                "exception_type": "AirflowAlertException",
                "status": "FAILED",
            },
            {
                "category": "SSH_DIAGNOSTIC",
                "severity": 3,
                "message": (
                    "local variable 'ssh_client' referenced before assignment"
                ),
                "exception_type": "UnboundLocalError",
                "status": "FAILED",
            },
        ),
        "expected_distinct_error_count": 2,
    },
    {
        "test_case_id": "ssh_session_inactive",
        "title": "Repeated inactive SSH session",
        "description": (
            "Creates three identical SSH errors to verify that duplicate "
            "details produce one diagnostic group."
        ),
        "batch_master": {
            "site_code": "MALTA",
            "proj_name": "FLIPCHIP",
            "dag_id": "flipchip_monitor_heartbreak_watchdog_pll",
            "batch_start_date": "2026-09-07 16:25:00",
            "min_severity": 3,
            "alert_status": "OPEN",
        },
        "batch_details": tuple(
            {
                "category": "SSH_CONNECTIVITY",
                "severity": 3,
                "message": "SSH session not active",
                "exception_type": "SSHException",
                "status": "FAILED",
            }
            for _ in range(3)
        ),
        "expected_distinct_error_count": 1,
    },
    {
        "test_case_id": "linux_watchdog_duplicate",
        "title": "Repeated duplicate-process alert",
        "description": (
            "Creates duplicate source rows reporting multiple Linux watchdog "
            "processes."
        ),
        "batch_master": {
            "site_code": "MALTA",
            "proj_name": "FLIPCHIP",
            "dag_id": "flipchip_monitor_linux_watchdog_pll",
            "batch_start_date": "2026-09-04 16:20:00",
            "min_severity": 1,
            "alert_status": "OPEN",
        },
        "batch_details": tuple(
            {
                "category": "LINUX_PROCESS",
                "severity": 1,
                "message": (
                    "More than one instance of "
                    "inference_watchdog_queue_threading.py is running. "
                    "Please check."
                ),
                "exception_type": "AirflowAlertException",
                "status": "FAILED",
            }
            for _ in range(2)
        ),
        "expected_distinct_error_count": 1,
    },
    {
        "test_case_id": "ml_probability_drift",
        "title": "Multiple ML probability warnings",
        "description": (
            "Creates duplicate probability warnings plus a different lower "
            "probability observation in one batch."
        ),
        "batch_master": {
            "site_code": "MALTA",
            "proj_name": "FLIPCHIP",
            "dag_id": "flipchip_monitor_ml",
            "batch_start_date": "2026-09-07 16:30:00",
            "min_severity": 2,
            "alert_status": "OPEN",
        },
        "batch_details": (
            {
                "category": "MODEL_DRIFT",
                "severity": 2,
                "message": (
                    "WARNING:Past 7 days has an average probability of 0.77, "
                    "which is below the threshold of 0.80"
                ),
                "exception_type": "AirflowAlertException",
                "status": "FAILED",
            },
            {
                "category": "MODEL_DRIFT",
                "severity": 2,
                "message": (
                    "WARNING:Past 7 days has an average probability of 0.75, "
                    "which is below the threshold of 0.80"
                ),
                "exception_type": "AirflowAlertException",
                "status": "FAILED",
            },
            {
                "category": "MODEL_DRIFT",
                "severity": 1,
                "message": (
                    "WARNING:Past 7 days has an average probability of 0.79, "
                    "which is below the threshold of 0.80"
                ),
                "exception_type": "ModelDriftWarning",
                "status": "FAILED",
            },
        ),
        "expected_distinct_error_count": 2,
    },
    {
        "test_case_id": "windows_watchdog_stopped",
        "title": "Repeated Windows watchdog alert",
        "description": (
            "Creates duplicate Windows watchdog failures for connectivity "
            "verification."
        ),
        "batch_master": {
            "site_code": "MALTA",
            "proj_name": "FLIPCHIP",
            "dag_id": "flipchip_monitor_windows_watchdog_pll",
            "batch_start_date": "2026-09-07 16:35:00",
            "min_severity": 1,
            "alert_status": "OPEN",
        },
        "batch_details": tuple(
            {
                "category": "WINDOWS_PROCESS",
                "severity": 1,
                "message": (
                    "Windows watchdog is not running. Please check if all 3 "
                    "watchdog is running."
                ),
                "exception_type": "AirflowAlertException",
                "status": "FAILED",
            }
            for _ in range(2)
        ),
        "expected_distinct_error_count": 1,
    },
    {
        "test_case_id": "ansible_web_recovery",
        "title": "Ansible web-service recovery",
        "description": (
            "Creates separate web and worker process alerts for the controlled "
            "Ansible recovery test component."
        ),
        "batch_master": {
            "site_code": "MALTA",
            "proj_name": "FLIPCHIP",
            "dag_id": "ansible_web_service_recovery_test",
            "batch_start_date": "2026-09-10 16:20:00",
            "min_severity": 3,
            "alert_status": "OPEN",
        },
        "batch_details": (
            {
                "category": "APPLICATION_PROCESS",
                "severity": 3,
                "message": "The Ansible web application may not be running.",
                "exception_type": "ServiceProcessUnavailable",
                "status": "FAILED",
            },
            {
                "category": "BACKGROUND_WORKER",
                "severity": 3,
                "message": "The Ansible background worker may not be running.",
                "exception_type": "ServiceProcessUnavailable",
                "status": "FAILED",
            },
        ),
        "expected_distinct_error_count": 2,
    },
    {
        "test_case_id": "aoiburr_ml_probability_low",
        "title": "AOI Burr model confidence below threshold",
        "description": (
            "Creates one Severity 2 AOI Burr model-performance alert for a "
            "seven-day average confidence below the configured 0.9 threshold."
        ),
        "batch_master": {
            "site_code": "MALTA",
            "proj_name": "AOIBURR",
            "dag_id": "aoiburr_monitor_ml",
            "batch_start_date": "2026-09-22 06:00:00",
            "min_severity": 2,
            "alert_status": "OPEN",
        },
        "batch_details": (
            {
                "category": "Model Performance",
                "severity": 2,
                "message": (
                    "WARNING:Past 7 days has an average probability of 0.873, "
                    "which is below the threshold of 0.9"
                ),
                "exception_type": "AirflowAlertException",
                "status": "FAILED",
            },
        ),
        "expected_distinct_error_count": 1,
    },
    {
        "test_case_id": "aoiburr_table_data_stale",
        "title": "AOI Burr output data freshness exceeded",
        "description": (
            "Creates one Severity 2 alert indicating that no non-null AOI "
            "Burr prediction was loaded during the previous four hours."
        ),
        "batch_master": {
            "site_code": "MALTA",
            "proj_name": "AOIBURR",
            "dag_id": "aoiburr_monitor_table_data",
            "batch_start_date": "2026-09-22 07:00:00",
            "min_severity": 2,
            "alert_status": "OPEN",
        },
        "batch_details": (
            {
                "category": "Output Data Freshness",
                "severity": 2,
                "message": (
                    "Data Freshness exceed for Table(t_aoiburrdata) - Last "
                    "Timestamp in LoadingTime where Prediction is not NULL : "
                    "2026-09-22 01:30:00"
                ),
                "exception_type": "AirflowAlertException",
                "status": "FAILED",
            },
        ),
        "expected_distinct_error_count": 1,
    },
    {
        "test_case_id": "axiimgclass_main_missing",
        "title": "AXI image classification main script missing",
        "description": (
            "Creates one Severity 4 missing-process alert for the AXI "
            "Classification ETL main script. The Verifier checks the live "
            "process count on KIRSX00317."
        ),
        "batch_master": {
            "site_code": "MALTA",
            "proj_name": "AXIIMGCLASS",
            "dag_id": "axiimgclass_monitor_main_pll",
            "batch_start_date": "2026-09-29 09:00:00",
            "min_severity": 4,
            "alert_status": "OPEN",
        },
        "batch_details": (
            {
                "category": "Data Pipeline",
                "severity": 4,
                "message": (
                    "AXI Classification ETL main.py is not running. "
                    "Please check."
                ),
                "exception_type": "AirflowAlertException",
                "status": "FAILED",
            },
        ),
        "expected_distinct_error_count": 1,
    },
    {
        "test_case_id": "axiimgclass_ml_probability_low",
        "title": "AXI image classification model probability low",
        "description": (
            "Creates two distinct Severity 2 model-performance alerts for "
            "AXI product lines. The Verifier queries live data through "
            "AXIIMGCLASS_PRD_DB."
        ),
        "batch_master": {
            "site_code": "MALTA",
            "proj_name": "AXIIMGCLASS",
            "dag_id": "axiimgclass_monitor_ml_binary_multiclass",
            "batch_start_date": "2026-09-29 06:00:00",
            "min_severity": 2,
            "alert_status": "OPEN",
        },
        "batch_details": (
            {
                "category": "Model Performance",
                "severity": 2,
                "message": (
                    "WARNING: [BDX6_FC80ABQ] has a 7-day moving average "
                    "probability of 0.932, which is below the threshold "
                    "(0.95)."
                ),
                "exception_type": "AirflowAlertException",
                "status": "FAILED",
            },
            {
                "category": "Model Performance",
                "severity": 2,
                "message": (
                    "WARNING: [SSHD_1T_FB74] has a 7-day moving average "
                    "probability of 0.884, which is below the threshold "
                    "(0.95)."
                ),
                "exception_type": "AirflowAlertException",
                "status": "FAILED",
            },
        ),
        "expected_distinct_error_count": 2,
    },
    {
        "test_case_id": "capillary_data_freshness_stale",
        "title": "Capillary output data older than 15 minutes",
        "description": (
            "Creates one Severity 2 output-data freshness alert for the "
            "Capillary merged table. The Verifier checks the live timestamp "
            "on CAPILLARY_PRD_DB."
        ),
        "batch_master": {
            "site_code": "MALTA",
            "proj_name": "CAPILLARY",
            "dag_id": "capillary_monitor_data_freshness",
            "batch_start_date": "2026-09-29 15:00:00",
            "min_severity": 2,
            "alert_status": "OPEN",
        },
        "batch_details": (
            {
                "category": "Output Data Freshness",
                "severity": 2,
                "message": (
                    "Table name: t_capillary_merged | Current time: "
                    "2026-09-29 15:00:00 | Data last refresh date: "
                    "2026-09-29 14:35:00 | Delayed by minutes: 25"
                ),
                "exception_type": "AirflowAlertException",
                "status": "FAILED",
            },
        ),
        "expected_distinct_error_count": 1,
    },
    {
        "test_case_id": "capillary_data_source_empty",
        "title": "Capillary input view returns no rows",
        "description": (
            "Creates one Severity 2 input-data alert when the Capillary "
            "source view returns zero rows. The Verifier checks the live "
            "row count on CAPILLARY_PRD_DB."
        ),
        "batch_master": {
            "site_code": "MALTA",
            "proj_name": "CAPILLARY",
            "dag_id": "capillary_monitor_data_source",
            "batch_start_date": "2026-09-29 15:05:00",
            "min_severity": 2,
            "alert_status": "OPEN",
        },
        "batch_details": (
            {
                "category": "Input Data Freshness",
                "severity": 2,
                "message": "Row Count for v_eqpattributes_capillary is <= 0",
                "exception_type": "AirflowAlertException",
                "status": "FAILED",
            },
        ),
        "expected_distinct_error_count": 1,
    },
    {
        "test_case_id": "tpakftavi_main_script_missing",
        "title": "TPAKFTAVI update script missing",
        "description": (
            "Creates one Severity 1 missing-process alert. The Verifier "
            "checks all three monitored scripts on SZS_SZSSXV00110_SSH."
        ),
        "batch_master": {
            "site_code": "SZS",
            "proj_name": "TPAKFTAVI",
            "dag_id": "tpakftavi_monitor_main_script",
            "batch_start_date": "2026-10-06 09:00:00",
            "min_severity": 1,
            "alert_status": "OPEN",
        },
        "batch_details": (
            {
                "category": "Data Pipeline",
                "severity": 1,
                "message": (
                    "No instances are running of "
                    "ftavi_update_restapi.py is running. Please check."
                ),
                "exception_type": "AirflowAlertException",
                "status": "FAILED",
            },
        ),
        "expected_distinct_error_count": 1,
    },
    {
        "test_case_id": "aoiburr_freshness_recovered_history",
        "title": "AOI Burr freshness alert with two historical observations",
        "description": (
            "Replays the exact freshness message from batch "
            "06102026_150003_aoiburr_monitor_table_data, preserving the "
            "15:00 and 16:00 DAG execution windows and the original latest "
            "qualifying LoadingTime of 2026-10-06 10:00:47. The Verifier "
            "must explain the historical evidence separately from its "
            "current live freshness check."
        ),
        "batch_master": {
            "site_code": "MALTA",
            "proj_name": "AOIBURR",
            "dag_id": "aoiburr_monitor_table_data",
            "batch_start_date": "2026-10-06 15:00:03",
            "min_severity": 2,
            "alert_status": "OPEN",
        },
        "batch_details": (
            {
                "dag_id": "aoiburr_monitor_table_data",
                "dag_startdate": "2026-10-06 15:00:03",
                "dag_enddate": "2026-10-06 15:00:15",
                "category": "Output Data Freshness",
                "severity": 2,
                "message": (
                    "Data Freshness exceed for Table(t_aoiburrdata) - Last "
                    "Timestamp in LoadingTime where Prediction is not NULL : "
                    "2026-10-06 10:00:47"
                ),
                "exception_type": "AirflowAlertException",
                "status": "ALERT",
            },
            {
                "dag_id": "aoiburr_monitor_table_data",
                "dag_startdate": "2026-10-06 16:00:04",
                "dag_enddate": "2026-10-06 16:00:14",
                "category": "Output Data Freshness",
                "severity": 2,
                "message": (
                    "Data Freshness exceed for Table(t_aoiburrdata) - Last "
                    "Timestamp in LoadingTime where Prediction is not NULL : "
                    "2026-10-06 10:00:47"
                ),
                "exception_type": "AirflowAlertException",
                "status": "ALERT",
            },
        ),
        "expected_distinct_error_count": 1,
    },
)


def get_test_case(test_case_id: str) -> Optional[dict[str, Any]]:
    return next(
        (
            case
            for case in TEST_CASES
            if case["test_case_id"] == test_case_id
        ),
        None,
    )