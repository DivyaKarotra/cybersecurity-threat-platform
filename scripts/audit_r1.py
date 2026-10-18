"""
Audit script for R1 Suspicious Auth rule detections and underlying authentication data.

Outputs:
1. Top 10 users by detections
2. Share of detections where user ends with '$' or is ANONYMOUS LOGON
3. Distinct src computers and users
4. Share of detections whose user or src computer is in the Red Team set
5. failed_attempts percentiles (50/90/99/max)
6. Count of detections per auth_type/logon_type if available (and in underlying Silver auth)
"""
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import numpy as np
import pandas as pd
import pyarrow.parquet as pq


def main():
    print("=" * 60)
    print("STEP 1: R1 AUDIT REPORT")
    print("=" * 60)

    # 1. Load Gold all_threats
    threats_path = PROJECT_ROOT / "data" / "gold" / "all_threats"
    if not threats_path.exists():
        print(f"Error: {threats_path} does not exist")
        return

    threats_df = pq.read_table(str(threats_path)).to_pandas()
    r1_df = threats_df[threats_df["threat_type"] == "R1_suspicious_auth"].copy()
    total_r1 = len(r1_df)
    print(f"Total R1 detections: {total_r1:,} of {len(threats_df):,} total threats ({total_r1/len(threats_df)*100:.2f}%)")

    # 1. Top 10 users by detections
    print("\n1. Top 10 users by detections:")
    top10_users = r1_df["user"].value_counts().head(10)
    for idx, (u, c) in enumerate(top10_users.items(), 1):
        print(f"   {idx:2d}. {u}: {c:,} ({c/total_r1*100:.2f}%)")

    # 2. Share of detections where user ends with '$' or is ANONYMOUS LOGON
    # Machine accounts in LANL / Windows: account part ending '$' (e.g. C2096$@DOM1, C2096$)
    is_machine_suffix = r1_df["user"].astype(str).str.strip().str.endswith("$")
    is_machine_domain = r1_df["user"].astype(str).apply(lambda x: x.split("@")[0].endswith("$") if "@" in x else x.endswith("$"))
    is_machine = is_machine_suffix | is_machine_domain
    is_anon = r1_df["user"].astype(str).str.contains("ANONYMOUS LOGON", case=False, na=False)
    is_excluded = is_machine | is_anon

    machine_count = is_machine.sum()
    anon_count = is_anon.sum()
    excluded_count = is_excluded.sum()

    print("\n2. Machine accounts and ANONYMOUS LOGON share:")
    print(f"   - Strict ends with '$': {is_machine_suffix.sum():,} ({is_machine_suffix.sum()/total_r1*100:.2f}%)")
    print(f"   - Machine account ($ before @ or at end): {machine_count:,} ({machine_count/total_r1*100:.2f}%)")
    print(f"   - ANONYMOUS LOGON: {anon_count:,} ({anon_count/total_r1*100:.2f}%)")
    print(f"   - Combined noise share: {excluded_count:,} ({excluded_count/total_r1*100:.2f}%)")

    # 3. Distinct src computers and users
    distinct_users = r1_df["user"].nunique(dropna=True)
    distinct_src_comp = r1_df["src_computer"].nunique(dropna=True)
    print("\n3. Distinct src computers and users:")
    print(f"   - Distinct users: {distinct_users:,}")
    print(f"   - Distinct src computers: {distinct_src_comp:,}")

    # 4. Share of detections whose user or src computer is in the Red Team set
    rt_path = PROJECT_ROOT / "data" / "silver" / "redteam"
    if rt_path.exists():
        rt_df = pq.read_table(str(rt_path)).to_pandas()
        rt_users = set(rt_df["user"].dropna().str.strip().str.upper()).union(
            set(rt_df["user_key"].dropna().str.strip().str.upper())
        )
        rt_src_comps = set(rt_df["src_computer"].dropna().str.strip().str.upper()).union(
            set(rt_df["src_computer_key"].dropna().str.strip().str.upper())
        )

        r1_user_norm = r1_df["user"].astype(str).str.strip().str.upper()
        r1_src_norm = r1_df["src_computer"].astype(str).str.strip().str.upper()

        in_rt_user = r1_user_norm.isin(rt_users)
        in_rt_src = r1_src_norm.isin(rt_src_comps)
        in_rt_either = in_rt_user | in_rt_src

        print("\n4. Red Team set overlap:")
        print(f"   - Distinct Red Team users: {len(rt_users):,}, src computers: {len(rt_src_comps):,}")
        print(f"   - Detections with user in RT: {in_rt_user.sum():,} ({in_rt_user.sum()/total_r1*100:.2f}%)")
        print(f"   - Detections with src_computer in RT: {in_rt_src.sum():,} ({in_rt_src.sum()/total_r1*100:.2f}%)")
        print(f"   - Detections with user OR src_computer in RT: {in_rt_either.sum():,} ({in_rt_either.sum()/total_r1*100:.2f}%)")
    else:
        print("\n4. Red Team dataset not found in Silver")

    # 5. failed_attempts percentiles (50/90/99/max)
    fails = r1_df["failed_attempts"]
    print("\n5. failed_attempts percentiles (in R1 detections):")
    print(f"   - 50th percentile (p50): {np.percentile(fails, 50):.1f}")
    print(f"   - 90th percentile (p90): {np.percentile(fails, 90):.1f}")
    print(f"   - 95th percentile (p95): {np.percentile(fails, 95):.1f}")
    print(f"   - 99th percentile (p99): {np.percentile(fails, 99):.1f}")
    print(f"   - max: {fails.max():.1f}")

    # 6. Count of detections per auth_type/logon_type if available
    print("\n6. Count of detections per auth_type/logon_type:")
    cols = set(r1_df.columns)
    if "auth_type" in cols or "logon_type" in cols:
        if "auth_type" in cols:
            print("   - auth_type breakdown:\n", r1_df["auth_type"].value_counts())
        if "logon_type" in cols:
            print("   - logon_type breakdown:\n", r1_df["logon_type"].value_counts())
    else:
        print("   - In Gold threat schema: auth_type and logon_type are not stored on detections.")
        # Check underlying Silver auth failed events if available
        silver_auth_path = PROJECT_ROOT / "data" / "silver" / "auth"
        if silver_auth_path.exists():
            print("   - In underlying Silver auth (failed events):")
            # Sample or check
            auth_by_type_path = PROJECT_ROOT / "data" / "gold" / "auth_by_type"
            if auth_by_type_path.exists():
                abt = pq.read_table(str(auth_by_type_path)).to_pandas()
                print("   - Overall auth distribution by auth_type (top 5):")
                top_auth = abt.groupby("auth_type")["count"].sum().sort_values(ascending=False).head(5)
                for at, cnt in top_auth.items():
                    print(f"     * {at}: {cnt:,}")
                print("   - Overall auth distribution by logon_type (top 5):")
                top_logon = abt.groupby("logon_type")["count"].sum().sort_values(ascending=False).head(5)
                for lt, cnt in top_logon.items():
                    print(f"     * {lt}: {cnt:,}")


if __name__ == "__main__":
    main()
