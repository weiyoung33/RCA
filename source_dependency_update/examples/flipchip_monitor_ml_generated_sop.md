# INVESTIGATION SOP FOR flipchip_monitor_ml

Component ID: flipchip_monitor_ml
Operating mode: INVESTIGATE_ONLY
Registered DATABASE target: FLIPCHIP_DB
- Procedure basis: validated DAG source.

Assess the current state using the following checks and source-derived calculations. Complete every required check.

Relative dates use the registered database calendar for this current-state procedure. The source uses the Airflow host date; this normalization does not establish that the two clocks share a timezone. Do not use these checks to reconstruct a historical run.

1. Run query_database on target 'FLIPCHIP_DB' with this exact read-only query:

```sql
SELECT DATE(DATE), MIN(confidence), MAX(confidence), COUNT(image), AVG(confidence)
FROM t_inference WHERE DATE < CURRENT_DATE() AND DATE >= CURRENT_DATE() - INTERVAL 30 DAY
GROUP BY DATE(DATE) ORDER BY DATE(DATE) DESC
```

2. Run query_database on target 'FLIPCHIP_DB' with this exact read-only query:

```sql
SELECT COUNT(DISTINCT SUBSTRING_INDEX(SUBSTRING_INDEX(Loaded_file, '_', 2), '_', -1)) AS LOT_number, DATE(LoadingTime)
FROM t_statistics WHERE DATE(LoadingTime) < CURRENT_DATE() AND DATE(LoadingTime) >= CURRENT_DATE() - INTERVAL 30 DAY
GROUP BY DATE(LoadingTime) ORDER BY DATE(LoadingTime) DESC
```

Before using this result, retain only the first (the number of the returned rows from step 1 + 1) rows, in the returned order. This preserves the source runtime LIMIT. The diagnostic retrieves the ordered rows before applying that limit; require a complete, untruncated result.

3. Run query_database on target 'FLIPCHIP_DB' with this exact read-only query:

```sql
SELECT COUNT(*) FROM t_inference WHERE DATE(date) = (CURRENT_DATE() - INTERVAL 1 DAY)
```

Calculate and interpret:
- summary records: the returned rows from step 1.
- nb records: the number of summary records.
- lot records: the returned rows from step 2.
- lot by date: a lookup from lot records, keyed by column 2 of each row in lot records, storing column 1 of each row in lot records.
- merged records: start with an empty list; for each row in summary records, append (column 1 of that row, column 2 of that row, column 3 of that row, column 4 of that row, column 5 of that row, lookup in lot by date at column 1 of that row (default 0), lookup in lot by date at column 1 of that row (default 0) < 2).
- observations yesterday: column 1 of the first row of the returned rows from step 3.
- filtered days: the rows from merged records where column 6 of each row in merged records ≥ 2.
- last 7 days: the first 7 rows of filtered days, preserving their order.
- num days: the number of last 7 days.
- average 7 days: (the sum of column 5 across last 7 days / num days) when num days > 0; otherwise NULL.

Classification:
- If ((observations yesterday > 0) and (average 7 days is not NULL)) and (average 7 days ≤ 0.8): MANUAL_REVIEW_REQUIRED.
- If ((observations yesterday > 0) and (average 7 days is not NULL)) and (average 7 days > 0.8): NO_REMEDIATION_REQUIRED.
- If no classification branch is established, use INCONCLUSIVE. A source branch that skips evaluation, including absent production or no qualifying measurements, does not establish model health.
- Missing, NULL, nonnumeric or nonfinite required measurements, invalid calculations, failed checks or truncated rows are INCONCLUSIVE. Never convert missing data to zero unless that exact default is specified in a calculation above.
- Report the current measurements and selected branch. A healthy current observation does not establish the cause or exact recovery time of an earlier alert.

Do not run database writes, restarts, process termination, DAG triggers, notifications or other state-changing operations. No automatic remediation is registered by this SOP.