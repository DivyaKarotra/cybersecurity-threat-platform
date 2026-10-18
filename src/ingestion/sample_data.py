"""
Sampling stage – event-window approach with Tier-1 priority and Tier-2 baseline.

For each of the 749 Red Team events, we build an interval
[event_time - WINDOW_PAD, event_time + WINDOW_PAD]. Overlapping intervals
are merged. A raw row is considered only if its timestamp falls inside any merged
interval.

Priority tiers:
  Tier 1 (UNCAPPED, tight): keep rows that can actually match Red Team inside
  the window [event_time - WINDOW_PAD, event_time + WINDOW_PAD]:
    - flows: src_computer_key/dst_computer_key equal to a Red Team (src, dst) pair,
      OR either side in the Red Team computer set.
    - proc: user_key in the Red Team user set OR computer_key in the Red Team
      src computer set.
    - dns: src_computer in Red Team src computer set.
    - auth: user in Red Team user set OR computer in Red Team computer set.
    - redteam: all rows kept.

  Tier 2 (baseline, never time-ordered cutoff): from the rest of the rows inside
  the merged Red Team windows, keep a deterministic hash sample at a FIXED rate
  set in config (flows 2%, proc 3%), applied across the whole time range.
  No "stop when full" logic anywhere.

Each source writes to a temporary file (.tmp) and atomically renames it
on completion. If an output file already exists, it is skipped unless --force.
"""
import argparse
from bisect import bisect_left, bisect_right
import gzip
import logging
from pathlib import Path
import sys
import time

# Add project root to path if run standalone
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from config.settings import (
    RAW_FILES, SAMPLE_DIR, WINDOW_PAD, TIER2_SAMPLE_RATES
)

logger = logging.getLogger(__name__)

ORDER = ["redteam", "dns", "flows", "proc", "auth"]


# ── Interval helpers ──────────────────────────────────────────────────────

def _build_merged_intervals(times: list, pad: int) -> list:
    """Build and merge [t - pad, t + pad] intervals. Returns sorted list of (lo, hi)."""
    raw = sorted(set((t - pad, t + pad) for t in times))
    if not raw:
        return []
    merged = [raw[0]]
    for lo, hi in raw[1:]:
        prev_lo, prev_hi = merged[-1]
        if lo <= prev_hi:
            merged[-1] = (prev_lo, max(prev_hi, hi))
        else:
            merged.append((lo, hi))
    return merged


# ── Red Team info ────────────────────────────────────────────────────────

def _load_redteam_info(path: Path):
    """
    Stream redteam.txt.gz to get:
    - rt_events: [(t, user, src, dst, idx), ...]
    - rt_users: set of upper-case user bytes
    - rt_src_computers: set of upper-case src computer bytes
    - rt_dst_computers: set of upper-case dst computer bytes
    - rt_computers: set of all upper-case computer bytes
    - rt_pairs: set of (src, dst) bytes tuples
    """
    rt_events = []
    with gzip.open(str(path), "rb") as f:
        idx = 0
        for line in f:
            parts = line.rstrip().split(b",")
            if len(parts) < 4:
                continue
            try:
                t = int(parts[0])
            except ValueError:
                continue
            u = parts[1].strip().upper()
            src = parts[2].strip().upper()
            dst = parts[3].strip().upper()
            rt_events.append((t, u, src, dst, idx))
            idx += 1

    rt_users = {e[1] for e in rt_events if e[1] and e[1] != b"?"}
    rt_src_computers = {e[2] for e in rt_events if e[2] and e[2] != b"?"}
    rt_dst_computers = {e[3] for e in rt_events if e[3] and e[3] != b"?"}
    rt_computers = rt_src_computers | rt_dst_computers
    rt_pairs = {(e[2], e[3]) for e in rt_events if e[2] and e[3] and e[2] != b"?" and e[3] != b"?"}

    return rt_events, rt_users, rt_src_computers, rt_dst_computers, rt_computers, rt_pairs


def _check_rt_event_matches(t: int, parts: list, source: str,
                            rt_times_sorted: list, rt_events_by_time: list,
                            pad: int, covered_set: set):
    """Check which RT events match this tier-1 row in both time and key, adding their indices to covered_set."""
    left = bisect_left(rt_times_sorted, t - pad)
    right = bisect_right(rt_times_sorted, t + pad)
    if left >= right:
        return

    if source == "flows":
        src = parts[2].strip().upper()
        dst = parts[4].strip().upper()
        for cand in rt_events_by_time[left:right]:
            cand_idx = cand[4]
            cand_src = cand[2]
            cand_dst = cand[3]
            if (src == cand_src and dst == cand_dst) or (src in (cand_src, cand_dst)) or (dst in (cand_src, cand_dst)):
                covered_set.add(cand_idx)

    elif source == "proc":
        user = parts[1].strip().upper()
        comp = parts[2].strip().upper()
        for cand in rt_events_by_time[left:right]:
            cand_idx = cand[4]
            cand_user = cand[1]
            cand_src = cand[2]
            if (user == cand_user) or (comp == cand_src):
                covered_set.add(cand_idx)

    elif source == "dns":
        src = parts[1].strip().upper()
        for cand in rt_events_by_time[left:right]:
            cand_idx = cand[4]
            cand_src = cand[2]
            if src == cand_src:
                covered_set.add(cand_idx)

    elif source == "auth":
        src_u = parts[1].strip().upper()
        src_c = parts[3].strip().upper()
        dst_c = parts[4].strip().upper()
        for cand in rt_events_by_time[left:right]:
            cand_idx = cand[4]
            cand_user = cand[1]
            cand_src = cand[2]
            cand_dst = cand[3]
            if (src_u == cand_user) or (src_c in (cand_src, cand_dst)) or (dst_c in (cand_src, cand_dst)):
                covered_set.add(cand_idx)


# ── Main sampling ────────────────────────────────────────────────────────

def sample_sources(force: bool = False, sources: list = None) -> dict:
    """
    Streaming pass per raw .gz file.
    Tier 1 is UNCAPPED; Tier 2 has a fixed baseline rate across the full time range.
    Writes to .tmp and renames to .csv on completion.
    Skips already existing samples unless force=True.
    """
    redteam_path = RAW_FILES["redteam"]
    (
        rt_events, rt_users, rt_src_computers, rt_dst_computers,
        rt_computers, rt_pairs
    ) = _load_redteam_info(redteam_path)

    if not rt_events:
        raise RuntimeError("No redteam events found – cannot determine sample windows")

    rt_times = [e[0] for e in rt_events]
    intervals = _build_merged_intervals(rt_times, WINDOW_PAD)
    min_interval_start = intervals[0][0]
    max_interval_end = intervals[-1][1]

    # Pre-sort for fast bisect
    rt_events_by_time = sorted(rt_events, key=lambda x: x[0])
    rt_times_sorted = [e[0] for e in rt_events_by_time]

    logger.info(f"Red Team: {len(rt_events)} events, {len(intervals)} merged intervals")
    logger.info(f"Intervals span: [{min_interval_start}, {max_interval_end}]")
    logger.info(f"Red Team computers: {len(rt_computers)} (src: {len(rt_src_computers)}), users: {len(rt_users)}, pairs: {len(rt_pairs)}")

    SAMPLE_DIR.mkdir(parents=True, exist_ok=True)
    stats = {}

    target_sources = sources if sources else ORDER

    for source in target_sources:
        path = RAW_FILES.get(source)
        if not path or not path.exists():
            logger.warning(f"Skipping {source}: file not found at {path}")
            continue

        out_path = SAMPLE_DIR / f"{source}.csv"
        tmp_path = SAMPLE_DIR / f"{source}.csv.tmp"

        if out_path.exists() and not force:
            logger.info(f"Skipping {source}: {out_path.name} already exists (use --force to overwrite)")
            continue

        fixed_rate = TIER2_SAMPLE_RATES.get(source, 0.02)
        fixed_threshold = int(round(fixed_rate * 10000))
        is_redteam = (source == "redteam")

        logger.info(f"Sampling {source} (Tier 1 uncapped, Tier 2 fixed baseline {fixed_rate*100:.1f}%)...")
        written = 0
        p1_count = 0
        p2_count = 0
        p2_ordinal = 0
        min_t = float("inf")
        max_t = float("-inf")
        total_read = 0
        rt_covered_events = set()
        curr_iv = 0

        # Remove any leftover temp file
        if tmp_path.exists():
            tmp_path.unlink()

        with gzip.open(str(path), "rb") as in_f, open(str(tmp_path), "wb") as out_f:
            for line in in_f:
                total_read += 1
                if total_read % 10_000_000 == 0:
                    logger.info(f"  {source}: {total_read:,} rows read, {written:,} kept (tier 1={p1_count:,}, tier 2={p2_count:,})")

                # Red Team file: keep everything
                if is_redteam:
                    out_f.write(line)
                    written += 1
                    p1_count += 1
                    c1 = line.find(b",")
                    if c1 != -1:
                        try:
                            t = int(line[:c1])
                            if t < min_t: min_t = t
                            if t > max_t: max_t = t
                        except ValueError:
                            pass
                    continue

                # Parse timestamp from first field
                c1 = line.find(b",")
                if c1 == -1:
                    continue
                try:
                    t = int(line[:c1])
                except ValueError:
                    continue

                # Quick discard if before first interval
                if t < min_interval_start:
                    continue

                # Advance current interval
                while curr_iv < len(intervals) and t > intervals[curr_iv][1]:
                    curr_iv += 1

                # If past all intervals, break out
                if curr_iv >= len(intervals):
                    break

                # If before current interval, skip
                if t < intervals[curr_iv][0]:
                    continue

                # Row is inside intervals[curr_iv]
                parts = line.rstrip().split(b",")

                # Check Tier 1 condition
                if source == "flows":
                    if len(parts) < 5:
                        continue
                    src = parts[2].strip().upper()
                    dst = parts[4].strip().upper()
                    is_t1 = ((src, dst) in rt_pairs) or (src in rt_computers) or (dst in rt_computers)
                elif source == "proc":
                    if len(parts) < 3:
                        continue
                    user = parts[1].strip().upper()
                    comp = parts[2].strip().upper()
                    is_t1 = (user in rt_users) or (comp in rt_src_computers)
                elif source == "dns":
                    if len(parts) < 2:
                        continue
                    src = parts[1].strip().upper()
                    is_t1 = (src in rt_src_computers)
                elif source == "auth":
                    if len(parts) < 5:
                        continue
                    src_u = parts[1].strip().upper()
                    src_c = parts[3].strip().upper()
                    dst_c = parts[4].strip().upper()
                    is_t1 = (src_u in rt_users) or (src_c in rt_computers) or (dst_c in rt_computers)
                else:
                    is_t1 = False

                if is_t1:
                    out_f.write(line)
                    written += 1
                    p1_count += 1
                    if t < min_t: min_t = t
                    if t > max_t: max_t = t
                    _check_rt_event_matches(t, parts, source, rt_times_sorted, rt_events_by_time, WINDOW_PAD, rt_covered_events)
                else:
                    # Tier 2 baseline: fixed deterministic hash sampling, uncapped
                    p2_ordinal += 1
                    if (((p2_ordinal * 2654435761) & 0xFFFFFFFF) % 10000) < fixed_threshold:
                        out_f.write(line)
                        written += 1
                        p2_count += 1
                        if t < min_t: min_t = t
                        if t > max_t: max_t = t

        # Atomic rename on completion
        tmp_path.replace(out_path)

        rt_covered = len(rt_covered_events) if not is_redteam else len(rt_events)
        stats[source] = {
            "total_read": total_read,
            "written": written,
            "p1_count": p1_count,
            "p2_count": p2_count,
            "min_time": min_t if min_t != float("inf") else None,
            "max_time": max_t if max_t != float("-inf") else None,
            "rt_events_covered": rt_covered,
        }

        summary_msg = (
            f"[SUMMARY] {source}: rows kept={written:,} (tier 1={p1_count:,}, tier 2={p2_count:,}), "
            f"min_time={stats[source]['min_time']}, max_time={stats[source]['max_time']}, "
            f"TRUE coverage={rt_covered}/{len(rt_events)} "
            f"({rt_covered / len(rt_events) * 100:.1f}%)"
        )
        logger.info(summary_msg)
        print(summary_msg, flush=True)

    return stats


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Sample raw event datasets.")
    parser.add_argument("--force", action="store_true", help="Force resampling even if sample file exists")
    parser.add_argument("--sources", nargs="+", default=None, help="Sources to sample (default: all)")
    args = parser.parse_args()

    sys.stdout.reconfigure(line_buffering=True)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
        stream=sys.stdout,
    )
    sample_sources(force=args.force, sources=args.sources)
