"""
Sampling stage – event-window approach.

For each of the 749 Red Team events, we build an interval
[event_time - WINDOW_PAD, event_time + WINDOW_PAD]. Overlapping intervals
are merged. A raw row is kept if its timestamp falls inside any merged
interval.

Priority system:
  1. Rows that touch a Red Team computer or user -> always kept.
  2. Other rows inside the interval -> hash-sampled to fill the per-source
     cap (MAX_ROWS_PER_SOURCE). P2 rows are capped so they never exhaust
     the budget before all Red Team windows are traversed.

Every Red Team row is always kept (source == "redteam").
Rows stay in original file order; no fabrication.

Order of processing: redteam, dns, flows, proc, auth (smallest first).
Each source writes to a temporary file (.tmp) and atomically renames it
on completion. If an output file already exists, it is skipped unless --force.
"""
import argparse
import gzip
import logging
import sys
import time
from pathlib import Path

# Add project root to path if run standalone
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from config.settings import (
    RAW_FILES, SAMPLE_DIR, WINDOW_PAD, MAX_ROWS_PER_SOURCE,
)

logger = logging.getLogger(__name__)

ORDER = ["redteam", "dns", "flows", "proc", "auth"]

# P2 hash-sampling rates and caps per source to ensure full temporal span
P2_CONFIG = {
    "redteam": {"rate": 1, "p2_cap": 3_000_000},
    "dns":     {"rate": 1, "p2_cap": 2_500_000},
    "flows":   {"rate": 10, "p2_cap": 2_000_000},
    "proc":    {"rate": 5, "p2_cap": 2_000_000},
    "auth":    {"rate": 15, "p2_cap": 1_500_000},
}


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


def _find_interval_index(t: int, intervals: list) -> int:
    """Return index of the interval containing t, or -1 (binary search)."""
    lo_idx, hi_idx = 0, len(intervals) - 1
    while lo_idx <= hi_idx:
        mid = (lo_idx + hi_idx) // 2
        ilo, ihi = intervals[mid]
        if t < ilo:
            hi_idx = mid - 1
        elif t > ihi:
            lo_idx = mid + 1
        else:
            return mid
    return -1


# ── Field-index helpers ──────────────────────────────────────────────────

def _get_field_indices(source: str):
    """Return (computer_col_indices, user_col_indices) for each source."""
    if source == "auth":
        return [3, 4], [1, 2]
    elif source == "dns":
        return [1, 2], []
    elif source == "flows":
        return [2, 4], []
    elif source == "proc":
        return [2], [1]
    elif source == "redteam":
        return [2, 3], [1]
    return [], []


def _is_priority1(parts: list, comp_indices: list, user_indices: list,
                   rt_comps: set, rt_users: set) -> bool:
    """Fast check whether row matches any Red Team computer or user."""
    for i in comp_indices:
        if i < len(parts):
            v = parts[i].strip().upper()
            if v and v != b"?" and v in rt_comps:
                return True
    for i in user_indices:
        if i < len(parts):
            v = parts[i].strip().upper()
            if v and v != b"?" and v in rt_users:
                return True
    return False


def _hash_sample(ordinal: int, rate: int) -> bool:
    """Deterministic hash-based sampling on row ordinal."""
    if rate <= 1:
        return True
    return (((ordinal * 2654435761) & 0xFFFFFFFF) % rate) == 0


# ── Red Team info ────────────────────────────────────────────────────────

def _load_redteam_info(path: Path):
    """Stream redteam.txt.gz to get times, computers, users (bytes)."""
    times = []
    computers = set()
    users = set()
    with gzip.open(str(path), "rb") as f:
        for line in f:
            parts = line.rstrip().split(b",")
            if len(parts) < 4:
                continue
            try:
                t = int(parts[0])
            except ValueError:
                continue
            times.append(t)
            user_raw = parts[1].strip()
            src_raw = parts[2].strip()
            dst_raw = parts[3].strip()
            if user_raw and user_raw != b"?":
                users.add(user_raw.upper())
            if src_raw and src_raw != b"?":
                computers.add(src_raw.upper())
            if dst_raw and dst_raw != b"?":
                computers.add(dst_raw.upper())
    return times, computers, users


# ── Main sampling ────────────────────────────────────────────────────────

def sample_sources(force: bool = False) -> dict:
    """
    Single streaming pass per raw .gz file.
    Order: redteam, dns, flows, proc, auth.
    Writes to .tmp and renames to .csv on completion.
    Skips already existing samples unless force=True.
    """
    redteam_path = RAW_FILES["redteam"]
    rt_times, rt_computers, rt_users = _load_redteam_info(redteam_path)

    if not rt_times:
        raise RuntimeError("No redteam events found – cannot determine sample windows")

    intervals = _build_merged_intervals(rt_times, WINDOW_PAD)
    min_interval_start = intervals[0][0]
    max_interval_end = intervals[-1][1]

    # Map each RT event to its interval so we can track per-event coverage
    rt_event_intervals = {}
    for t in rt_times:
        idx = _find_interval_index(t, intervals)
        rt_event_intervals[t] = idx

    logger.info(f"Red Team: {len(rt_times)} events, {len(intervals)} merged intervals")
    logger.info(f"Intervals span: [{min_interval_start}, {max_interval_end}]")
    logger.info(f"Red Team computers: {len(rt_computers)}, users: {len(rt_users)}")

    SAMPLE_DIR.mkdir(parents=True, exist_ok=True)
    stats = {}

    for source in ORDER:
        path = RAW_FILES.get(source)
        if not path or not path.exists():
            logger.warning(f"Skipping {source}: file not found at {path}")
            continue

        out_path = SAMPLE_DIR / f"{source}.csv"
        tmp_path = SAMPLE_DIR / f"{source}.csv.tmp"

        if out_path.exists() and not force:
            logger.info(f"Skipping {source}: {out_path.name} already exists (use --force to overwrite)")
            continue

        comp_indices, user_indices = _get_field_indices(source)
        cfg = P2_CONFIG.get(source, {"rate": 10, "p2_cap": 2_000_000})
        p2_rate = cfg["rate"]
        p2_cap = cfg["p2_cap"]
        cap = MAX_ROWS_PER_SOURCE
        is_redteam = (source == "redteam")

        logger.info(f"Sampling {source} (single streaming pass)...")
        written = 0
        p1_count = 0
        p2_count = 0
        p2_ordinal = 0
        min_t = float("inf")
        max_t = float("-inf")
        total_read = 0
        intervals_hit = set()
        last_iv_idx = 0

        # Remove any leftover temp file
        if tmp_path.exists():
            tmp_path.unlink()

        with gzip.open(str(path), "rb") as in_f, open(str(tmp_path), "wb") as out_f:
            for line in in_f:
                total_read += 1
                if total_read % 10_000_000 == 0:
                    logger.info(f"  {source}: {total_read:,} rows read, {written:,} kept")

                # Parse timestamp from first field (fast)
                comma_idx = line.find(b",")
                if comma_idx == -1:
                    continue
                try:
                    t = int(line[:comma_idx])
                except ValueError:
                    continue

                # Quick discard if before first interval or after last interval
                if t < min_interval_start:
                    continue
                if t > max_interval_end:
                    break

                # Interval check with cache of last matched interval
                if last_iv_idx < len(intervals) and intervals[last_iv_idx][0] <= t <= intervals[last_iv_idx][1]:
                    iv_idx = last_iv_idx
                else:
                    iv_idx = _find_interval_index(t, intervals)
                    if iv_idx >= 0:
                        last_iv_idx = iv_idx
                    else:
                        continue

                # Red Team file: keep everything
                if is_redteam:
                    out_f.write(line)
                    written += 1
                    intervals_hit.add(iv_idx)
                    if t < min_t:
                        min_t = t
                    if t > max_t:
                        max_t = t
                    continue

                # Priority check
                parts = line.rstrip().split(b",")
                is_p1 = _is_priority1(parts, comp_indices, user_indices,
                                       rt_computers, rt_users)

                if is_p1:
                    out_f.write(line)
                    written += 1
                    p1_count += 1
                    intervals_hit.add(iv_idx)
                    if t < min_t:
                        min_t = t
                    if t > max_t:
                        max_t = t
                else:
                    p2_ordinal += 1
                    if p2_count < p2_cap and (written < cap - 50_000):
                        if _hash_sample(p2_ordinal, p2_rate):
                            out_f.write(line)
                            written += 1
                            p2_count += 1
                            intervals_hit.add(iv_idx)
                            if t < min_t:
                                min_t = t
                            if t > max_t:
                                max_t = t

                if written >= cap:
                    logger.info(f"  {source}: reached cap of {cap:,} rows, stopping.")
                    break

        # Atomic rename on completion
        tmp_path.replace(out_path)

        # Count how many of the 749 RT events have coverage
        rt_covered = 0
        for rt_t, iv_idx in rt_event_intervals.items():
            if iv_idx in intervals_hit:
                rt_covered += 1

        stats[source] = {
            "total_read": total_read,
            "written": written,
            "p1_count": p1_count if not is_redteam else written,
            "min_time": min_t if min_t != float("inf") else None,
            "max_time": max_t if max_t != float("-inf") else None,
            "rt_events_covered": rt_covered,
        }

        summary_msg = (
            f"[SUMMARY] {source}: rows kept={written:,}, "
            f"min_time={stats[source]['min_time']}, max_time={stats[source]['max_time']}, "
            f"RT covered={rt_covered}/{len(rt_times)} "
            f"({rt_covered / len(rt_times) * 100:.1f}%)"
        )
        logger.info(summary_msg)
        print(summary_msg, flush=True)

    return stats


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Sample raw event datasets.")
    parser.add_argument("--force", action="store_true", help="Force resampling even if sample file exists")
    args = parser.parse_args()

    sys.stdout.reconfigure(line_buffering=True)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
        stream=sys.stdout,
    )
    sample_sources(force=args.force)
