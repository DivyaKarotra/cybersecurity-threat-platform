import pyarrow.parquet as pq
import pandas as pd
import numpy as np
import sys
from pathlib import Path

# Load redteam
rt_df = pq.read_table('data/silver/redteam').to_pandas()
rt_count = len(rt_df)
rt_min, rt_max = rt_df['time'].min(), rt_df['time'].max()
rt_under_170k = (rt_df['time'] <= 169945).sum()
rt_pairs = set(zip(rt_df['src_computer_key'], rt_df['dst_computer_key']))
rt_users = set(rt_df['user_key'].dropna())

output_lines = []
output_lines.append(f"RedTeam Total: {rt_count}, min_t: {rt_min}, max_t: {rt_max}, t<=169945: {rt_under_170k} ({rt_under_170k/rt_count*100:.1f}%)")
output_lines.append(f"Distinct RT Pairs: {len(rt_pairs)}, Distinct RT Users: {len(rt_users)}")
output_lines.append("-" * 85)
output_lines.append(f"{'Source':<8} | {'Rows':<10} | {'Min Time':<9} | {'Max Time':<9} | {'RT Pairs':<9} | {'RT Users':<9} | {'True RT Covered':<15}")
output_lines.append("-" * 85)

WINDOW_PAD = 600

for src in ['auth', 'dns', 'flows', 'proc']:
    src_dir = Path(f'data/silver/{src}')
    if not src_dir.exists():
        continue
    df = pq.read_table(str(src_dir)).to_pandas()
    count = len(df)
    if count == 0:
        continue
    min_t, max_t = df['time'].min(), df['time'].max()
    
    # Sort by time for binary search
    df = df.sort_values('time').reset_index(drop=True)
    df_times = df['time'].values

    # Check distinct key overlaps
    if 'src_computer_key' in df.columns and 'dst_computer_key' in df.columns:
        s_pairs = set(zip(df['src_computer_key'], df['dst_computer_key']))
        matched_pairs = f"{len(rt_pairs.intersection(s_pairs))}/{len(rt_pairs)}"
    elif 'src_computer_key' in df.columns and 'resolved_computer_key' in df.columns:
        s_pairs = set(zip(df['src_computer_key'], df['resolved_computer_key']))
        matched_pairs = f"{len(rt_pairs.intersection(s_pairs))}/{len(rt_pairs)}"
    else:
        matched_pairs = "N/A"

    u_cols = [c for c in ['src_user_key', 'dst_user_key', 'user_key'] if c in df.columns]
    if u_cols:
        s_users = set()
        for c in u_cols:
            s_users.update(df[c].dropna())
        matched_users = f"{len(rt_users.intersection(s_users))}/{len(rt_users)}"
    else:
        matched_users = "N/A"

    # Compute TRUE coverage: Red Team events with at least one actual key+time match
    true_covered = 0
    if src == 'flows':
        src_keys = df['src_computer_key'].values
        dst_keys = df['dst_computer_key'].values
        for _, r in rt_df.iterrows():
            t_rt, s_rt, d_rt = r['time'], r['src_computer_key'], r['dst_computer_key']
            l = np.searchsorted(df_times, t_rt - WINDOW_PAD)
            r_idx = np.searchsorted(df_times, t_rt + WINDOW_PAD, side='right')
            if l < r_idx:
                sub_s = src_keys[l:r_idx]
                sub_d = dst_keys[l:r_idx]
                if np.any((sub_s == s_rt) & (sub_d == d_rt)) or np.any((sub_s == s_rt) | (sub_s == d_rt) | (sub_d == s_rt) | (sub_d == d_rt)):
                    true_covered += 1

    elif src == 'proc':
        user_keys = df['user_key'].values
        comp_keys = df['computer_key'].values
        for _, r in rt_df.iterrows():
            t_rt, u_rt, s_rt = r['time'], r['user_key'], r['src_computer_key']
            l = np.searchsorted(df_times, t_rt - WINDOW_PAD)
            r_idx = np.searchsorted(df_times, t_rt + WINDOW_PAD, side='right')
            if l < r_idx:
                sub_u = user_keys[l:r_idx]
                sub_c = comp_keys[l:r_idx]
                if np.any(sub_u == u_rt) or np.any(sub_c == s_rt):
                    true_covered += 1

    elif src == 'dns':
        src_keys = df['src_computer_key'].values
        for _, r in rt_df.iterrows():
            t_rt, s_rt = r['time'], r['src_computer_key']
            l = np.searchsorted(df_times, t_rt - WINDOW_PAD)
            r_idx = np.searchsorted(df_times, t_rt + WINDOW_PAD, side='right')
            if l < r_idx:
                sub_s = src_keys[l:r_idx]
                if np.any(sub_s == s_rt):
                    true_covered += 1

    elif src == 'auth':
        src_users = df['src_user_key'].values
        src_comps = df['src_computer_key'].values
        dst_comps = df['dst_computer_key'].values
        for _, r in rt_df.iterrows():
            t_rt, u_rt, s_rt, d_rt = r['time'], r['user_key'], r['src_computer_key'], r['dst_computer_key']
            l = np.searchsorted(df_times, t_rt - WINDOW_PAD)
            r_idx = np.searchsorted(df_times, t_rt + WINDOW_PAD, side='right')
            if l < r_idx:
                sub_u = src_users[l:r_idx]
                sub_s = src_comps[l:r_idx]
                sub_d = dst_comps[l:r_idx]
                if np.any(sub_u == u_rt) or np.any((sub_s == s_rt) | (sub_s == d_rt) | (sub_d == s_rt) | (sub_d == d_rt)):
                    true_covered += 1

    share = true_covered / rt_count * 100
    output_lines.append(f"{src:<8} | {count:<10,d} | {min_t:<9} | {max_t:<9} | {matched_pairs:<9} | {matched_users:<9} | {true_covered}/{rt_count} ({share:.1f}%)")

output_text = "\n".join(output_lines)
print(output_text)

if "--save" in sys.argv:
    Path("ALIGNMENT.md").write_text(output_text + "\n", encoding="utf-8")
