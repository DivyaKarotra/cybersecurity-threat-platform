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

## Sampling & Alignment Record (2026-10-18 - True Coverage Resampling)
- **redteam**: 749 events, [150885, 2557047]
- **flows**: 5,714,310 rows (tier 1: 5,481,010, tier 2: 233,300), True RT covered: 592/749 (79.0%) [LIMITATION: recorded as limitation per STEP 2]
- **proc**: 816,177 rows (tier 1: 100,274, tier 2: 715,903), True RT covered: 424/749 (56.6%) [LIMITATION: recorded as limitation per STEP 2]
- **dns**: 607,933 rows, True RT covered: 18/749 (2.4%)
- **auth**: 3,000,000 rows, True RT covered: 34/749 (4.5%) [Pending Step 4]

*Note: Per STEP 2 instructions, recorded exact true coverage numbers as limitations and continuing without resampling.*
