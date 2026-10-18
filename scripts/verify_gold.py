"""
Verification script for Gold layer threat detections and severity breakdown.
"""
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import pandas as pd
import pyarrow.parquet as pq


def main():
    threats_path = PROJECT_ROOT / "data" / "gold" / "all_threats"
    if not threats_path.exists():
        print(f"Error: {threats_path} does not exist")
        sys.exit(1)

    df = pq.read_table(str(threats_path)).to_pandas()
    print("=" * 60)
    print("GOLD LAYER THREAT VERIFICATION REPORT")
    print("=" * 60)
    print(f"Total threats: {len(df):,}")

    print("\n--- Threat Counts by Type ---")
    by_type = df["threat_type"].value_counts()
    for t, c in by_type.items():
        print(f"  {t:<25}: {c:,} ({c/len(df)*100:.2f}%)")

    print("\n--- Threat Counts by Severity ---")
    by_sev = df["severity"].value_counts()
    for s, c in by_sev.items():
        print(f"  {s:<10}: {c:,} ({c/len(df)*100:.2f}%)")

    print("\n--- Cross-Tabulation (Type x Severity) ---")
    ct = pd.crosstab(df["threat_type"], df["severity"], margins=True)
    print(ct.to_string())

    print("\n--- Red Team Corroboration Breakdown for R1 ---")
    r1 = df[df["threat_type"] == "R1_suspicious_auth"]
    print(f"  R1 total: {len(r1):,}")
    print(f"  R1 Medium: {(r1['severity'] == 'Medium').sum():,}")
    print(f"  R1 Critical (RT corroborated): {(r1['severity'] == 'Critical').sum():,}")
    print(f"  R1 High: {(r1['severity'] == 'High').sum():,}")
    print(f"  R1 Low: {(r1['severity'] == 'Low').sum():,}")


if __name__ == "__main__":
    main()
