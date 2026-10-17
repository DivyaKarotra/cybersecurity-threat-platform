# Cybersecurity Threat Detection Platform

LANL Cyber1 dataset analysis with PySpark, Bronze/Silver/Gold medallion architecture, and Streamlit dashboard.

## Architecture

```
Raw .gz files → [Inspect] → [Sample] → Bronze (typed Parquet)
                                         → Silver (cleaned, join keys)
                                           → Threat Rules (R1–R5)
                                             → Gold (analytics, stats)
                                               → Dashboard (Streamlit)
```

### Medallion Layers

| Layer  | Description |
|--------|-------------|
| **Bronze** | Raw typed Parquet from sampled CSVs. Explicit schemas, `?` → null, no cleaning. |
| **Silver** | Standardised snake_case, normalised join keys (upper-case, trimmed), drop malformed rows, `is_failure` bool for auth. Original identifiers preserved. |
| **Gold** | Unified threat detections, summaries, risk profiles, per-source analytics. |

## Dataset

[LANL Unified Host and Network Dataset](https://csr.lanl.gov/data/2017/) (Cyber1):
- **auth.txt.gz** – Authentication events (time, users, computers, auth/logon type, success/fail)
- **dns.txt.gz** – DNS lookups (time, src_computer, resolved_computer)
- **flows.txt.gz** – Network flows (time, duration, src/dst computer/port, protocol, packets, bytes)
- **proc.txt.gz** – Process events (time, user, computer, process, start/end)
- **redteam.txt.gz** – Red team compromise events (time, user, src/dst computer)

All comma-delimited, no header, `?` = missing, time = integer seconds from dataset start.

## Threat Detection Rules

| Rule | Name | How a Match Forms |
|------|------|-------------------|
| R1 | Suspicious Authentication | ≥5 failed logons by same (src_user, src_computer, dst_computer) within 300s tumbling window |
| R2 | RedTeam + Flow | Network flow matching redteam src→dst computers within ±300s. Deduped by distinct redteam event. |
| R3 | RedTeam + DNS | DNS query from redteam src_computer within ±300s. Description states resolved target. |
| R4 | Suspicious Process | Per (user, computer, process) frequency > mean + 3×std across computers. Top-20 widespread processes excluded. |
| R5 | RedTeam + Process | Process by redteam user on redteam src_computer within ±300s window. |

### Risk Scoring Formula
```
score = base + failure_bonus + count_bonus + redteam_bonus    (capped 0–100)
  base:           R1=40, R2=70, R3=55, R4=35, R5=75
  failure_bonus:  min(failed_attempts × 2, 20)
  count_bonus:    min((event_count - 1) × 1, 15)
  redteam_bonus:  10 if rule involves redteam correlation
```

**Severity**: 0–39 Low, 40–69 Medium, 70–89 High, 90–100 Critical.

## Setup (Windows PowerShell)

```powershell
cd cybersecurity-threat-platform
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt

# Ensure raw data is at ../data/raw/{auth,dns,flows,proc,redteam}.txt.gz
```

### Prerequisites
- Python 3.13+
- Java 21+ (OpenJDK)
- HADOOP_HOME / winutils: not required for local mode on modern PySpark 3.5+

## Run

```powershell
# Full pipeline
.\venv\Scripts\python.exe run_pipeline.py

# Skip sampling (reuse existing samples)
.\venv\Scripts\python.exe run_pipeline.py --skip-sample

# Run single stage
.\venv\Scripts\python.exe run_pipeline.py --stage silver
```

### Pipeline Stages (in order)
`inspect → sample → bronze → silver → rule_R1 → rule_R2 → rule_R3 → rule_R4 → rule_R5 → combine → gold → validate`

## Tests

```powershell
.\venv\Scripts\python.exe -m pytest tests/ -v
```

Each rule has positive (known-trigger) and negative (known-safe) test cases. Tests use synthetic fixtures that are never written to Gold.

## Dashboard

```powershell
.\venv\Scripts\python.exe -m streamlit run dashboard/app.py
```

Features: KPI cards, threats by rule/severity, risk histogram, top users/computers, recent threats table, sidebar filters (severity, type, time range). Handles empty Gold gracefully.

## Output Folders

| Folder | Contents |
|--------|----------|
| `data/sample/` | Time-windowed CSV samples |
| `data/bronze/` | Typed Parquet per source |
| `data/silver/` | Cleaned Parquet with join keys |
| `data/gold/` | all_threats, summary_by_type, summary_by_severity, high_risk, statistics, user_risk, computer_risk, flow_*, auth_*, dns_*, process_*, redteam_* |

## Validation

`src/utils/validate.py` checks: schema, no unexpected NULLs in required fields, risk score bounds, severity values, duplicate detections, statistics reconciliation, Bronze→Silver row counts.

## Known Limitations

- Sampling uses a time window around Red Team events (padded ±1h). Events outside this window are not analysed.
- R4 (Suspicious Process) uses mean+3×std which may produce many detections on skewed distributions; configurable via `PROC_STDDEV_MULTIPLIER`.
- Tumbling window for R1 may split a burst across bucket boundaries (documented approximation).
- Dashboard uses pandas (not Spark) so very large Gold tables may be slow to render.
- Time values are integer seconds from dataset start, not wall-clock timestamps.
