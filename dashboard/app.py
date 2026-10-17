"""
Streamlit dashboard for Cybersecurity Threat Detection Platform.
Reads Gold Parquet with pandas/pyarrow only (no Spark).
Handles empty Gold data gracefully.
"""
import sys
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import streamlit as st
import pandas as pd
import json

from config.settings import GOLD_DIR

st.set_page_config(
    page_title="Cyber Threat Detection Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Custom CSS ─────────────────────────────────────────────────────────────
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');

    .stApp {
        font-family: 'Inter', sans-serif;
    }
    .main-header {
        background: linear-gradient(135deg, #0f0c29, #302b63, #24243e);
        padding: 1.5rem 2rem;
        border-radius: 12px;
        margin-bottom: 1.5rem;
        color: white;
    }
    .main-header h1 {
        color: #00d4ff;
        margin: 0;
        font-weight: 700;
    }
    .main-header p {
        color: #a0aec0;
        margin: 0.3rem 0 0 0;
    }
    .kpi-card {
        background: linear-gradient(135deg, #1a1a2e, #16213e);
        border: 1px solid #2d3748;
        border-radius: 10px;
        padding: 1.2rem;
        text-align: center;
        transition: transform 0.2s, box-shadow 0.2s;
    }
    .kpi-card:hover {
        transform: translateY(-2px);
        box-shadow: 0 4px 20px rgba(0, 212, 255, 0.15);
    }
    .kpi-value {
        font-size: 2.2rem;
        font-weight: 700;
        color: #00d4ff;
        line-height: 1.2;
    }
    .kpi-label {
        font-size: 0.85rem;
        color: #a0aec0;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        margin-top: 0.3rem;
    }
    .severity-critical { color: #ff4757; font-weight: 700; }
    .severity-high { color: #ff6b35; font-weight: 600; }
    .severity-medium { color: #ffa502; }
    .severity-low { color: #2ed573; }
    div[data-testid="stSidebar"] {
        background: linear-gradient(180deg, #0f0c29, #1a1a2e);
    }
    div[data-testid="stSidebar"] .stMarkdown p,
    div[data-testid="stSidebar"] label {
        color: #e2e8f0;
    }
</style>
""", unsafe_allow_html=True)


def load_parquet_safe(name: str) -> pd.DataFrame:
    """Load a Gold Parquet table, return empty DataFrame on error."""
    path = GOLD_DIR / name
    if not path.exists():
        return pd.DataFrame()
    try:
        return pd.read_parquet(str(path))
    except Exception:
        return pd.DataFrame()


def load_stats() -> dict:
    """Load statistics JSON from Gold."""
    df = load_parquet_safe("statistics")
    if df.empty or "stats_json" not in df.columns:
        return {}
    try:
        return json.loads(df.iloc[0]["stats_json"])
    except Exception:
        return {}


# ── Load Data ──────────────────────────────────────────────────────────────
threats = load_parquet_safe("all_threats")
stats = load_stats()
summary_type = load_parquet_safe("summary_by_type")
summary_sev = load_parquet_safe("summary_by_severity")
high_risk = load_parquet_safe("high_risk")
user_risk = load_parquet_safe("user_risk")
computer_risk = load_parquet_safe("computer_risk")

# ── Header ─────────────────────────────────────────────────────────────────
st.markdown("""
<div class="main-header">
    <h1>🛡️ Cyber Threat Detection Dashboard</h1>
    <p>LANL Cyber1 Dataset · Bronze/Silver/Gold Medallion Architecture · PySpark Analytics</p>
</div>
""", unsafe_allow_html=True)

if threats.empty:
    st.warning("⚠️ No threat data found in Gold layer. Run the pipeline first: `python run_pipeline.py`")
    st.stop()

# ── Sidebar Filters ───────────────────────────────────────────────────────
st.sidebar.markdown("## 🔍 Filters")

severity_options = sorted(threats["severity"].dropna().unique().tolist())
selected_severities = st.sidebar.multiselect(
    "Severity", severity_options, default=severity_options
)

type_options = sorted(threats["threat_type"].dropna().unique().tolist())
selected_types = st.sidebar.multiselect(
    "Threat Type", type_options, default=type_options
)

if "time" in threats.columns and threats["time"].notna().any():
    min_time = int(threats["time"].min())
    max_time = int(threats["time"].max())
    if min_time < max_time:
        time_range = st.sidebar.slider(
            "Time Range", min_time, max_time, (min_time, max_time)
        )
    else:
        time_range = (min_time, max_time)
else:
    time_range = None

# Apply filters
filtered = threats.copy()
filtered = filtered[filtered["severity"].isin(selected_severities)]
filtered = filtered[filtered["threat_type"].isin(selected_types)]
if time_range:
    filtered = filtered[
        (filtered["time"] >= time_range[0]) & (filtered["time"] <= time_range[1])
    ]

# ── KPI Cards ─────────────────────────────────────────────────────────────
st.markdown("### 📊 Key Performance Indicators")
cols = st.columns(5)

kpis = [
    ("Total Threats", stats.get("total_threats", len(threats))),
    ("Unique Users", stats.get("unique_users", threats["user"].nunique())),
    ("Unique Computers", stats.get("unique_computers", 0)),
    ("High+Critical", stats.get("high_critical_count", 0)),
    ("Avg Risk Score", stats.get("avg_risk_score", 0)),
]

for col, (label, value) in zip(cols, kpis):
    with col:
        if isinstance(value, float):
            val_str = f"{value:.1f}"
        else:
            val_str = f"{value:,}" if isinstance(value, int) else str(value)
        st.markdown(f"""
        <div class="kpi-card">
            <div class="kpi-value">{val_str}</div>
            <div class="kpi-label">{label}</div>
        </div>
        """, unsafe_allow_html=True)

st.markdown("---")

# ── Charts Row 1 ──────────────────────────────────────────────────────────
col1, col2 = st.columns(2)

with col1:
    st.markdown("### 🎯 Threats by Rule")
    if not filtered.empty:
        type_counts = filtered["threat_type"].value_counts().reset_index()
        type_counts.columns = ["Threat Type", "Count"]
        st.bar_chart(type_counts.set_index("Threat Type"))
    else:
        st.info("No threats match current filters")

with col2:
    st.markdown("### 🔴 Threats by Severity")
    if not filtered.empty:
        sev_counts = filtered["severity"].value_counts().reset_index()
        sev_counts.columns = ["Severity", "Count"]
        # Order by severity
        sev_order = ["Critical", "High", "Medium", "Low"]
        sev_counts["sort_key"] = sev_counts["Severity"].map(
            {s: i for i, s in enumerate(sev_order)}
        )
        sev_counts = sev_counts.sort_values("sort_key").drop("sort_key", axis=1)
        st.bar_chart(sev_counts.set_index("Severity"))
    else:
        st.info("No threats match current filters")

# ── Charts Row 2 ──────────────────────────────────────────────────────────
col3, col4 = st.columns(2)

with col3:
    st.markdown("### 📈 Risk Score Distribution")
    if not filtered.empty and "risk_score" in filtered.columns:
        st.bar_chart(
            filtered["risk_score"].value_counts().sort_index().reset_index().rename(
                columns={"index": "Risk Score", "risk_score": "Risk Score", "count": "Count"}
            ).set_index("Risk Score")
        )
    else:
        st.info("No data")

with col4:
    st.markdown("### 👤 Top 10 Users by Max Risk")
    if not user_risk.empty:
        top_users = user_risk.head(10)[["user", "threat_count", "max_risk", "avg_risk"]]
        st.dataframe(top_users, use_container_width=True, hide_index=True)
    else:
        st.info("No user risk data")

# ── Top Computers ─────────────────────────────────────────────────────────
st.markdown("### 💻 Top 10 Computers by Max Risk")
if not computer_risk.empty:
    top_comps = computer_risk.head(10)[["computer", "threat_count", "max_risk", "avg_risk"]]
    st.dataframe(top_comps, use_container_width=True, hide_index=True)
else:
    st.info("No computer risk data")

# ── Recent Threats Table ──────────────────────────────────────────────────
st.markdown("### 🔔 Recent Threats")
if not filtered.empty:
    display_cols = ["time", "threat_type", "severity", "risk_score", "user",
                    "src_computer", "dst_computer", "description"]
    available_cols = [c for c in display_cols if c in filtered.columns]
    recent = filtered.sort_values("time", ascending=False).head(50)[available_cols]

    def color_severity(val):
        colors = {
            "Critical": "color: #ff4757; font-weight: bold",
            "High": "color: #ff6b35; font-weight: bold",
            "Medium": "color: #ffa502",
            "Low": "color: #2ed573",
        }
        return colors.get(val, "")

    styled = recent.style.applymap(color_severity, subset=["severity"] if "severity" in available_cols else [])
    st.dataframe(styled, use_container_width=True, hide_index=True, height=400)
else:
    st.info("No threats match current filters")

# ── Footer ────────────────────────────────────────────────────────────────
st.markdown("---")
st.markdown(
    "<p style='text-align:center; color:#718096; font-size:0.8rem;'>"
    "Cybersecurity Threat Detection Platform · LANL Cyber1 Dataset · "
    "Built with PySpark + Streamlit</p>",
    unsafe_allow_html=True
)
