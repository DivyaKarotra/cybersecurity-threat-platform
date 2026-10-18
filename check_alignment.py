import pyarrow.parquet as pq
import pandas as pd

# Load redteam
rt_df = pq.read_table('data/silver/redteam').to_pandas()
rt_count = len(rt_df)
rt_min, rt_max = rt_df['time'].min(), rt_df['time'].max()
rt_under_170k = (rt_df['time'] <= 169945).sum()
rt_pairs = set(zip(rt_df['src_computer_key'], rt_df['dst_computer_key']))
rt_users = set(rt_df['user_key'].dropna())

print(f"RedTeam Total: {rt_count}, min_t: {rt_min}, max_t: {rt_max}, t<=169945: {rt_under_170k} ({rt_under_170k/rt_count*100:.1f}%)")
print(f"Distinct RT Pairs: {len(rt_pairs)}, Distinct RT Users: {len(rt_users)}")
print("-" * 80)
print(f"{'Source':<8} | {'Rows':<10} | {'Min Time':<9} | {'Max Time':<9} | {'RT Pairs':<9} | {'RT Users':<9} | {'RT Covered':<12}")
print("-" * 80)

for src in ['auth', 'dns', 'flows', 'proc']:
    df = pq.read_table(f'data/silver/{src}').to_pandas()
    min_t, max_t, count = df['time'].min(), df['time'].max(), len(df)
    
    # Check pairs
    if 'src_computer_key' in df.columns and 'dst_computer_key' in df.columns:
        s_pairs = set(zip(df['src_computer_key'], df['dst_computer_key']))
        matched_pairs = f"{len(rt_pairs.intersection(s_pairs))}/{len(rt_pairs)}"
    elif 'src_computer_key' in df.columns and 'resolved_computer_key' in df.columns:
        s_pairs = set(zip(df['src_computer_key'], df['resolved_computer_key']))
        matched_pairs = f"{len(rt_pairs.intersection(s_pairs))}/{len(rt_pairs)}"
    else:
        matched_pairs = "N/A"

    # Check users
    u_cols = [c for c in ['src_user_key', 'dst_user_key', 'user_key'] if c in df.columns]
    if u_cols:
        s_users = set()
        for c in u_cols:
            s_users.update(df[c].dropna())
        matched_users = f"{len(rt_users.intersection(s_users))}/{len(rt_users)}"
    else:
        matched_users = "N/A"

    # Check how many redteam events fall in [min_t, max_t]
    rt_in_win = ((rt_df['time'] >= min_t) & (rt_df['time'] <= max_t)).sum()
    share = rt_in_win / rt_count * 100
    print(f"{src:<8} | {count:<10,d} | {min_t:<9} | {max_t:<9} | {matched_pairs:<9} | {matched_users:<9} | {rt_in_win}/{rt_count} ({share:.1f}%)")
