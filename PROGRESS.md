# Pipeline Progress

| Stage | Status | Notes |
|---|---|---|
| config/settings.py | DONE | All paths, thresholds, windows, tightened R1 settings |
| inspect | DONE | Schema and raw file parameters verified |
| sample | DONE | Ordered streaming, atomic temp-file rename, skip-if-exists |
| bronze | DONE | Ingested to Parquet (auth: 39.78M, dns: 607k, flows: 5.71M, proc: 816k, redteam: 749) |
| silver | DONE | Cleaned & typed (auth: 39.78M, dns: 607k, flows: 5.71M, proc: 816k, redteam: 749; 0 dropped) |
| per-source analytics | DONE | Flow, auth, dns, proc, redteam analytics written to Gold |
| rules (R1-R5) | DONE | R1: 1,304, R2: 6, R3: 10, R4: 351, R5: 9 (Total: 1,680 detections; 24/24 pytests passed) |
| gold | DONE | Written Parquet: all_threats (1,680), summary (by type, severity), high_risk (25), statistics, user_risk, computer_risk, per-source analytics |
| validate | DONE | validate.py passed (ExitCode 0; schema OK, 0 dups, 0 required nulls, stats reconcile, Bronze/Silver reconcile) |
| pytest | DONE | 24/24 passing (threat rules, machine account exclusion, red team bonus, risk scoring, identifier normalisation, schema, deduplication, null markers, shared statistics, validation) |
| dashboard | DONE | dashboard/app.py written (pandas/pyarrow, real-time filtering, KPIs) |
| README | DONE | README.md updated with tightened R1 criteria, exclusions, data presence explanation, behavioural limitation, and verified Gold statistics |
| requirements.txt | DONE | Packages configured |
| .gitignore | DONE | Written (data/, logs/, scratch/, venv*, .pytest_cache ignored) |
| src modules | DONE | All .py files clean, modular, typed |
| Step 1: Audit R1 | DONE | Compact audit completed: top users dominated by machine accounts (52.5% ending $); 3,488 users, 3,261 src computers; 0.11% RT overlap; failed_attempts p50=8, p90=14, p95=23, p99=69; per-window p50=2, p95=9, p99=19; scripts/audit_r1.py committed |
| Step 2: Tighten R1 in Place | DONE | Config updated: AUTH_FAIL_THRESHOLD=20 (p95-based >= max(20, p95)), AUTH_FAIL_WINDOW=300s; machine accounts ($) and ANONYMOUS LOGON excluded; consecutive windows collapsed using island-gap grouping; Red Team corroboration bonus (+25) applied; uncorroborated R1 capped at Medium (<= 69); 2 new pytests added (24/24 pass) |
| Step 3: Rebuild & Verify | DONE | run_pipeline.py --skip-sample completed in 280.00s; validate.py passed; full pytest passed 24/24; Gold threat count tightened from 143,658 to 1,680 (R1: 1,304); High/Critical (25) reserved 100% for Red Team corroborated detections |
| Step 4: Documentation & Final Verification | DONE | README.md, ALIGNMENT.md, PROGRESS.md updated with real outputs; git status clean |

## Overall Status: DONE

## Sampling & Alignment Record (2026-10-18 - True Coverage Resampling)
- **redteam**: 749 events, [150885, 2557047]
- **flows**: 5,714,310 rows, True RT covered: 592/749 (79.0%)
- **proc**: 816,177 rows, True RT covered: 424/749 (56.6%)
- **dns**: 607,933 rows, True RT covered: 18/749 (2.4%)
- **auth**: 39,783,344 rows (tier_fail: 2,885,813, tier_rt: 36,755,014, tier_baseline: 142,517), True RT covered: 749/749 (100.0%)

## Final Gold Threat Statistics
- **Total Threats**: 1,680 (0 duplicates, 0 unexpected nulls)
- **By Rule**:
  - `R1_suspicious_auth`: 1,304 (77.62%)
  - `R4_suspicious_process`: 351 (20.89%)
  - `R3_redteam_dns`: 10 (0.60%)
  - `R5_redteam_process`: 9 (0.54%)
  - `R2_redteam_flow`: 6 (0.36%)
- **By Severity**:
  - `Medium`: 1,625 (96.73%)
  - `Low`: 30 (1.79%)
  - `Critical`: 21 (1.25%) — 9 from R1 (RT corroborated), 5 from R2, 7 from R5
  - `High`: 4 (0.24%) — 1 from R2, 1 from R3, 2 from R5
- **High & Critical Corroboration**: Exactly 25 threats are High/Critical, 100% corroborated by ground-truth Red Team activity.
- **Unique Users Flagged**: 339
- **Unique Computers Flagged**: 405 (378 source computers, 153 destination computers)
- **Average Risk Score**: 64.52
