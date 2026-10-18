# Pipeline Progress

| Stage | Status | Notes |
|-------|--------|-------|
| config/settings.py | DONE | All paths, thresholds, windows |
| inspect | DONE | Schema and raw file parameters verified |
| sample | DONE | Ordered streaming, atomic temp-file rename, skip-if-exists |
| bronze | DONE | Ingested to Parquet (auth: 3M, dns: 607k, flows: 3M, proc: 3M, redteam: 749) |
| silver | DONE | Cleaned & typed (auth: 3M, dns: 607k, flows: 3M, proc: 3M, redteam: 749; 0 dropped) |
| rules (R1-R5) | PENDING | Ready for execution |
| gold | PENDING | Not run |
| validate | PENDING | Not run |
| pytest | PENDING | Ready for testing |
| dashboard | DONE | dashboard/app.py written |
| README | DONE | README.md written |
| requirements.txt | DONE | Packages configured |
| .gitignore | DONE | Written |
| src modules | DONE | All .py files exist, non-empty |

## Sampling & Alignment Record (2026-10-18)
- **redteam**: 749 events, [150885, 2557047]
- **dns**: 607,933 rows, RT covered: 739/749 (98.7%) [Target >= 80% MET]
- **proc**: 3,000,000 rows, RT covered: 509/749 (68.0%) [LIMITATION: 3M cap reached at t=1092569]
- **flows**: 3,000,000 rows, RT covered: 168/749 (22.4%) [LIMITATION: 3M cap reached at t=756318]
- **auth**: 3,000,000 rows, RT covered: 30/749 (4.0%) [LIMITATION: 3M cap reached at t=464225]

*Note: Per STEP 3 instructions, recorded exact coverage numbers as limitations and continuing without resampling.*
