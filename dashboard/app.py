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
    page_title="Threat Detection Dashboard",
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
    div[data-testid="stCaptionContainer"] {
        text-align: center;
    }

    /* Selected chips (multiselect tags): muted blue #1F6FEB background, white text */
    span[data-baseweb="tag"],
    div[data-baseweb="tag"] {
        background-color: #1F6FEB !important;
        color: #FFFFFF !important;
        border: none !important;
        border-radius: 4px !important;
    }
    span[data-baseweb="tag"] span,
    div[data-baseweb="tag"] span,
    span[data-baseweb="tag"] div,
    div[data-baseweb="tag"] div {
        color: #FFFFFF !important;
    }
    span[data-baseweb="tag"] svg,
    div[data-baseweb="tag"] svg {
        fill: #FFFFFF !important;
        color: #FFFFFF !important;
    }

    /* Open dropdown list: background #1E2430, 1px border #3A4358, option text #E6EDF3, hover/selected option background #2D3A55, rounded corners, subtle shadow */
    div[data-baseweb="popover"] {
        border-radius: 8px !important;
    }
    div[data-baseweb="popover"] > div {
        background-color: #1E2430 !important;
        border: 1px solid #3A4358 !important;
        border-radius: 8px !important;
        box-shadow: 0 4px 16px rgba(0, 0, 0, 0.4) !important;
    }
    ul[role="listbox"] {
        background-color: #1E2430 !important;
        border-radius: 8px !important;
        padding: 4px 0 !important;
    }
    li[role="option"] {
        background-color: #1E2430 !important;
        color: #E6EDF3 !important;
        font-size: 0.9rem !important;
        transition: background-color 0.15s ease !important;
    }
    li[role="option"] span,
    li[role="option"] div,
    li[role="option"] p {
        color: #E6EDF3 !important;
    }
    li[role="option"]:hover,
    li[role="option"][aria-selected="true"],
    li[role="option"]:focus {
        background-color: #2D3A55 !important;
        color: #FFFFFF !important;
    }
    li[role="option"]:hover span,
    li[role="option"][aria-selected="true"] span,
    li[role="option"]:focus span,
    li[role="option"]:hover div,
    li[role="option"][aria-selected="true"] div,
    li[role="option"]:focus div {
        color: #FFFFFF !important;
    }

    /* Slider track/handles using blue #1F6FEB */
    div[data-baseweb="slider"] [role="slider"] {
        background-color: #1F6FEB !important;
        border-color: #1F6FEB !important;
        box-shadow: 0 0 0 2px rgba(31, 111, 235, 0.3) !important;
    }
    div[data-baseweb="slider"] [role="slider"]:focus,
    div[data-baseweb="slider"] [role="slider"]:active {
        box-shadow: 0 0 0 4px rgba(31, 111, 235, 0.4) !important;
    }
    div[data-testid="stSlider"] div[data-baseweb="slider"] > div > div:nth-child(2) {
        background-color: #1F6FEB !important;
    }
    div[data-testid="stSlider"] div[data-baseweb="slider"] div[style*="background-color: rgb(255"],
    div[data-testid="stSlider"] div[data-baseweb="slider"] div[style*="background: rgb(255"],
    div[data-testid="stSlider"] div[data-baseweb="slider"] div[style*="#ff"] {
        background-color: #1F6FEB !important;
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


def compute_kpis(df: pd.DataFrame) -> dict:
    """Compute KPI metrics from filtered DataFrame using pandas only."""
    if df.empty:
        return {
            "total_threats": 0,
            "unique_users": 0,
            "unique_computers": 0,
            "high_critical": 0,
            "avg_risk_score": 0.0,
        }
    total = len(df)
    users = int(df["user"].dropna().nunique()) if "user" in df.columns else 0
    if "src_computer" in df.columns and "dst_computer" in df.columns:
        comps = len(set(df["src_computer"].dropna()).union(set(df["dst_computer"].dropna())))
    elif "src_computer" in df.columns:
        comps = int(df["src_computer"].dropna().nunique())
    elif "dst_computer" in df.columns:
        comps = int(df["dst_computer"].dropna().nunique())
    else:
        comps = 0
    high_crit = int(df["severity"].isin(["High", "Critical"]).sum()) if "severity" in df.columns else 0
    avg_risk = float(df["risk_score"].mean()) if ("risk_score" in df.columns and df["risk_score"].notna().any()) else 0.0
    return {
        "total_threats": total,
        "unique_users": users,
        "unique_computers": comps,
        "high_critical": high_crit,
        "avg_risk_score": round(avg_risk, 1),
    }


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
    <h1>Threat Detection Dashboard</h1>
    <p>LANL Cyber1 Dataset · Bronze/Silver/Gold Medallion Architecture · PySpark Analytics</p>
</div>
""", unsafe_allow_html=True)

if threats.empty:
    st.warning("No threat data found in Gold layer. Run the pipeline first: `python run_pipeline.py`")
    st.stop()

# ── Sidebar Filters ───────────────────────────────────────────────────────
st.sidebar.markdown("## Filters")

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
st.markdown("### Key Metrics")

kpi_metrics = compute_kpis(filtered)

total_overall = stats.get("total_threats", len(threats))
users_overall = stats.get(
    "unique_users",
    int(threats["user"].dropna().nunique()) if "user" in threats.columns else 0,
)
comps_overall = stats.get(
    "unique_computers",
    len(set(threats["src_computer"].dropna()).union(set(threats["dst_computer"].dropna())))
    if ("src_computer" in threats.columns and "dst_computer" in threats.columns)
    else 0,
)
hc_overall = stats.get(
    "high_critical_count",
    int(threats["severity"].isin(["High", "Critical"]).sum()) if "severity" in threats.columns else 0,
)
avg_risk_overall = stats.get(
    "avg_risk_score",
    float(threats["risk_score"].mean()) if "risk_score" in threats.columns else 0.0,
)

cols = st.columns(5)

kpis = [
    ("Total Threats", kpi_metrics["total_threats"], f"Overall: {total_overall:,} threats"),
    ("Unique Users", kpi_metrics["unique_users"], f"Overall: {users_overall:,} users"),
    ("Unique Computers", kpi_metrics["unique_computers"], f"Overall: {comps_overall:,} computers"),
    ("High+Critical", kpi_metrics["high_critical"], f"Overall: {hc_overall:,} high+critical"),
    ("Avg Risk Score", kpi_metrics["avg_risk_score"], f"Overall: {avg_risk_overall:.1f} avg score"),
]

for col, (label, value, caption) in zip(cols, kpis):
    with col:
        if filtered.empty:
            val_str = "0"
        elif isinstance(value, float):
            val_str = f"{value:.1f}"
        else:
            val_str = f"{value:,}" if isinstance(value, int) else str(value)
        st.markdown(f"""
        <div class="kpi-card">
            <div class="kpi-value">{val_str}</div>
            <div class="kpi-label">{label}</div>
        </div>
        """, unsafe_allow_html=True)
        st.caption(caption)

if filtered.empty:
    st.info("No threats match the current filters")

st.markdown("---")

# ── Charts Row 1 ──────────────────────────────────────────────────────────
col1, col2 = st.columns(2)

with col1:
    st.markdown("### Threats by Rule")
    if not filtered.empty:
        type_counts = filtered["threat_type"].value_counts().reset_index()
        type_counts.columns = ["Threat Type", "Count"]
        st.bar_chart(type_counts.set_index("Threat Type"))
    else:
        st.info("No threats match the current filters")

with col2:
    st.markdown("### Threats by Severity")
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
        st.info("No threats match the current filters")

# ── Charts Row 2 ──────────────────────────────────────────────────────────
col3, col4 = st.columns(2)

with col3:
    st.markdown("### Risk Score Distribution")
    if not filtered.empty and "risk_score" in filtered.columns:
        st.bar_chart(
            filtered["risk_score"].value_counts().sort_index().reset_index().rename(
                columns={"index": "Risk Score", "risk_score": "Risk Score", "count": "Count"}
            ).set_index("Risk Score")
        )
    else:
        st.info("No threats match the current filters")

with col4:
    st.markdown("### Top 10 Users by Max Risk")
    if not user_risk.empty:
        top_users = user_risk.head(10)[["user", "threat_count", "max_risk", "avg_risk"]]
        st.dataframe(top_users, use_container_width=True, hide_index=True)
    else:
        st.info("No user risk data")

# ── Top Computers ─────────────────────────────────────────────────────────
st.markdown("### Top 10 Computers by Max Risk")
if not computer_risk.empty:
    top_comps = computer_risk.head(10)[["computer", "threat_count", "max_risk", "avg_risk"]]
    st.dataframe(top_comps, use_container_width=True, hide_index=True)
else:
    st.info("No computer risk data")

# ── Recent Threats Table ──────────────────────────────────────────────────
st.markdown("### Recent Threats")
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

    if hasattr(recent.style, "map"):
        styled = recent.style.map(color_severity, subset=["severity"] if "severity" in available_cols else [])
    else:
        styled = recent.style.applymap(color_severity, subset=["severity"] if "severity" in available_cols else [])
    st.dataframe(styled, use_container_width=True, hide_index=True, height=400)
else:
    st.info("No threats match the current filters")

# ── Footer ────────────────────────────────────────────────────────────────
st.markdown("---")
st.markdown(
    "<p style='text-align:center; color:#718096; font-size:0.8rem;'>"
    "Cybersecurity Threat Detection Platform · LANL Cyber1 Dataset · "
    "Built with PySpark + Streamlit</p>",
    unsafe_allow_html=True
)

