# Pipeline Progress

| Stage | Status | Notes |
|-------|--------|-------|
| config/settings.py | DONE | All paths, thresholds, windows |
| inspect | DONE | Schema and raw file parameters verified |
| sample | DONE | Ordered streaming, atomic temp-file rename, skip-if-exists |
| bronze | DONE | Ingested to Parquet (auth: 3M, dns: 607k, flows: 5.7M, proc: 816k, redteam: 749) |
| silver | DONE | Cleaned & typed (auth: 3M, dns: 607k, flows: 5.7M, proc: 816k, redteam: 749; 0 dropped) |
| per-source analytics | DONE | Flow, auth, dns, proc, redteam analytics written to Gold |
| rules (R1-R5) | DONE | R1: 550, R2: 7, R3: 12, R4: 908, R5: 9 (Total: 1,486 detections; all 17 pytests passed) |
| gold | DONE | Written Parquet: all_threats (926), summary (by type, severity), high_risk (62), statistics, user_risk, computer_risk, per-source analytics |
| validate | DONE | validate.py passed (ExitCode 0; schema OK, 0 dups, 0 required nulls, stats reconcile, Bronze/Silver reconcile) |
| pytest | DONE | 22/22 passing in 108.50s (threat rules, risk scoring, identifier normalisation, schema, deduplication, null markers, shared statistics, validation) |
| dashboard | DONE | dashboard/app.py written |
| README | DONE | README.md written |
| requirements.txt | DONE | Packages configured |
| .gitignore | DONE | Written |
| src modules | DONE | All .py files exist, non-empty |
| Stage A: Audit R4 & R1 | DONE | R1: 550 (90 groups, failed min 5, med 8, max 49); R4 tightened: 387 (0.70x R1, max share 4.57%, top comp C19932: 22); 17/17 pytests passed |
| Stage B: Combine & Risk Scoring | DONE | Combined: 962 threats (0 dups, 0 nulls); R1: 550, R2: 6, R3: 10, R4: 387, R5: 9; Low: 33, Med: 867, High: 50, Crit: 12; 19/19 pytests passed |
| Stage C: Gold Layer | DONE | 926 threats (0 dups, 0 required nulls); high_risk: 62, stats: 248 users, 237 computers; all Gold tables & source analytics written |
| Stage D: Validation | DONE | validate.py passed (ExitCode 0; schema OK, 0 dups, 0 required nulls, stats reconcile, Bronze/Silver reconcile) |
| Stage E: Full Pytest Suite | DONE | 22/22 pytests passed (100% pass rate in 108.50s) |
| Stage F: Pipeline End-to-End | DONE | run_pipeline.py --skip-sample completed in 199.68s; validate.py passed on result (926 threats, 0 dups, 0 required nulls) |
| Stage G: Dashboard Verification | DONE | Streamlit started headless, responded HTTP 200 OK, stopped cleanly |
| Stage H: README Documentation | DONE | Comprehensive README.md written with architecture, rules, setup, commands, and Known Limitations |
| Stage I: Requirements & Gitignore | DONE | requirements.txt pinned to direct venv versions (pyspark, pyarrow, pandas, streamlit, pytest); data/, logs/, venv/ verified in .gitignore |
| Step 1: Dashboard Check | DONE | Verified pandas/pyarrow read, KPIs, all/single filters (Medium: 834, R1: 550), and empty-Gold fallback |
| Step 2: README Accuracy | DONE | Aligned all figures with Gold statistics and ALIGNMENT.md; documented R1 dominant contribution (550/926, 59.4%) vs 4.5% auth coverage, and 2.4% dns coverage |
| Step 3: Python Version Check | DONE | Detected Python 3.12 (py -0); created venv311, ran 22/22 pytests (pass) and run_pipeline.py --skip-sample (160.26s pass, validation pass); documented venv311 in README.md |
| Step 4: Auth Resample (R1 Coverage) | DONE | Detached pass completed: kept 39,783,344 rows (tier_fail=2,885,813, tier_rt=36,755,014, tier_baseline=142,517); True RT covered: 749/749 (100.0%, up from 4.5%); Bronze/Silver rebuilt; Pipeline passed (143,658 threats, R1: 143,282, 0 dups, 0 unexpected nulls); 22/22 pytests passed |
| Step 5: Final Check | DONE | 22/22 pytests passed (52.34s); pipeline completed (300.72s); validate.py passed (ExitCode 0, 143,658 threats, 0 dups, 0 nulls); clean git status; data/, logs/, venv/, venv311/ ignored in .gitignore |

## Overall Status: DONE

## Sampling & Alignment Record (2026-10-18 - True Coverage Resampling)
- **redteam**: 749 events, [150885, 2557047]
- **flows**: 5,714,310 rows (tier 1: 5,481,010, tier 2: 233,300), True RT covered: 592/749 (79.0%)
- **proc**: 816,177 rows (tier 1: 100,274, tier 2: 715,903), True RT covered: 424/749 (56.6%)
- **dns**: 607,933 rows, True RT covered: 18/749 (2.4%)
- **auth**: 39,783,344 rows (tier_fail: 2,885,813, tier_rt: 36,755,014, tier_baseline: 142,517), True RT covered: 749/749 (100.0%)

