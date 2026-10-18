"""
Central configuration for the Cybersecurity Threat Platform.
All paths are relative to PROJECT_ROOT. All thresholds and windows are here.
"""
from pathlib import Path
import sys

# ── Paths ──────────────────────────────────────────────────────────────────
PROJECT_ROOT = Path(__file__).resolve().parent.parent
# Raw data lives OUTSIDE this project, in the parent Cybersecurity Project
RAW_DATA_DIR = PROJECT_ROOT.parent / "data" / "raw"
DATA_DIR = PROJECT_ROOT / "data"
SAMPLE_DIR = DATA_DIR / "sample"
BRONZE_DIR = DATA_DIR / "bronze"
SILVER_DIR = DATA_DIR / "silver"
GOLD_DIR = DATA_DIR / "gold"
SCHEMA_REF = PROJECT_ROOT / "config" / "schema_reference.json"

# ── Source files ───────────────────────────────────────────────────────────
SOURCES = ["auth", "dns", "flows", "proc", "redteam"]
RAW_FILES = {s: RAW_DATA_DIR / f"{s}.txt.gz" for s in SOURCES}

# ── Sampling ───────────────────────────────────────────────────────────────
WINDOW_PAD = 600           # seconds of padding around each redteam event
MAX_ROWS_PER_SOURCE = 3_000_000
WINDOW_WIDEN_STEP = 7200   # if time-overlap is empty, widen by this much
TIER2_SAMPLE_RATES = {
    "flows": 0.02,  # 2%
    "proc": 0.03,   # 3%
    "auth": 0.01,   # 1%
}

# ── Spark ──────────────────────────────────────────────────────────────────
SPARK_DRIVER_MEMORY = "4g"
SPARK_SHUFFLE_PARTITIONS = 16
PYSPARK_PYTHON = sys.executable

# ── Threat Detection Windows & Thresholds ──────────────────────────────────
# R1 – Suspicious Auth
AUTH_FAIL_THRESHOLD = 5       # minimum failed logons to flag
AUTH_FAIL_WINDOW = 300        # seconds

# R2 – RedTeam + Flow correlation
REDTEAM_FLOW_WINDOW = 300    # seconds

# R3 – RedTeam + DNS correlation
REDTEAM_DNS_WINDOW = 300     # seconds

# R4 – Suspicious Process
PROC_STDDEV_MULTIPLIER = 3   # count > mean + N * std
PROC_TOP_N_EXCLUDE = 20      # exclude top-N most widespread processes

# R5 – RedTeam + Process correlation
REDTEAM_PROC_WINDOW = 300    # seconds

# ── Risk Scoring ───────────────────────────────────────────────────────────
# Formula: base + failure_bonus + count_bonus + redteam_bonus, capped [0,100]
# Base per rule:
RISK_BASE = {
    "R1_suspicious_auth": 40,
    "R2_redteam_flow": 70,
    "R3_redteam_dns": 55,
    "R4_suspicious_process": 35,
    "R5_redteam_process": 75,
}
# Bonuses (additive, applied where relevant):
RISK_FAILURE_BONUS_PER = 2     # per failed attempt, max 20
RISK_FAILURE_BONUS_CAP = 20
RISK_COUNT_BONUS_PER = 1       # per event_count above 1, max 15
RISK_COUNT_BONUS_CAP = 15
RISK_REDTEAM_BONUS = 10        # if threat type involves redteam corroboration

# Severity thresholds
SEVERITY_THRESHOLDS = {
    "Low": (0, 39),
    "Medium": (40, 69),
    "High": (70, 89),
    "Critical": (90, 100),
}

# ── Gold Analytics Thresholds ──────────────────────────────────────────────
HIGH_VOLUME_FLOW_THRESHOLD = 1_000_000   # bytes
