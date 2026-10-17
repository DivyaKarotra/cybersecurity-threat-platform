"""
Sampling stage: reads .gz streams in a single pass, keeps rows within the time
window covering all Red Team events (padded by WINDOW_PAD). Uses deterministic
hash-based sampling for background rows to respect MAX_ROWS_PER_SOURCE, and
preserves redteam computers and users within the window.
Writes CSVs to data/sample/.
"""
import gzip
import logging
from pathlib import Path

from config.settings import (
    RAW_FILES, SAMPLE_DIR, WINDOW_PAD, MAX_ROWS_PER_SOURCE,
    WINDOW_WIDEN_STEP,
)

logger = logging.getLogger(__name__)

# Sample rates for background rows to ensure fast single-pass processing
# while keeping total rows around MAX_ROWS_PER_SOURCE
BACKGROUND_SAMPLE_RATES = {
    "redteam": 1,
    "dns": 2,
    "flows": 15,
    "proc": 20,
    "auth": 40,
}


def _load_redteam_info(path: Path):
    """Stream redteam.txt.gz to get time range and set of computers/users in bytes."""
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


def _get_field_indices(source: str):
    """Return (computer_indices, user_indices) for each source."""
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


def _is_redteam_related(parts: list, comp_indices: list, user_indices: list,
                         rt_comps: set, rt_users: set) -> bool:
    """Fast check whether row matches any redteam computer or user."""
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


def sample_sources() -> dict:
    """
    Single-pass sampling:
    Streams each .gz file once in binary mode.
    Keeps rows in [t_start, t_end], stops as soon as t > t_end or written reaches cap.
    Writes sampled CSVs to data/sample/.
    """
    redteam_path = RAW_FILES["redteam"]
    rt_times, rt_computers, rt_users = _load_redteam_info(redteam_path)

    if not rt_times:
        raise RuntimeError("No redteam events found – cannot determine sample window")

    t_start = min(rt_times) - WINDOW_PAD
    t_end = max(rt_times) + WINDOW_PAD
    logger.info(f"Red Team time range: [{min(rt_times)}, {max(rt_times)}]")
    logger.info(f"Sample window (padded): [{t_start}, {t_end}]")
    logger.info(f"Red Team computers: {len(rt_computers)}, users: {len(rt_users)}")

    SAMPLE_DIR.mkdir(parents=True, exist_ok=True)
    stats = {}

    for source in RAW_FILES:
        path = RAW_FILES[source]
        if not path.exists():
            logger.warning(f"Skipping {source}: file not found")
            continue

        comp_indices, user_indices = _get_field_indices(source)
        rate = BACKGROUND_SAMPLE_RATES.get(source, 10)
        out_path = SAMPLE_DIR / f"{source}.csv"

        logger.info(f"Sampling {source} (single pass)...")
        written = 0
        in_window = 0
        min_t = float("inf")
        max_t = float("-inf")
        ordinal = 0

        with gzip.open(str(path), "rb") as in_f, open(str(out_path), "wb") as out_f:
            for line in in_f:
                comma_idx = line.find(b",")
                if comma_idx == -1:
                    continue
                try:
                    t = int(line[:comma_idx])
                except ValueError:
                    continue

                if t < t_start:
                    continue
                if t > t_end:
                    # Data is time-sorted; past the window, we can stop immediately
                    break

                in_window += 1
                ordinal += 1

                parts = line.rstrip().split(b",")
                is_rt = source == "redteam" or _is_redteam_related(
                    parts, comp_indices, user_indices, rt_computers, rt_users
                )

                if is_rt or _hash_sample(ordinal, rate):
                    out_f.write(line)
                    written += 1
                    if t < min_t:
                        min_t = t
                    if t > max_t:
                        max_t = t
                    if written >= MAX_ROWS_PER_SOURCE:
                        break

        stats[source] = {
            "in_window": in_window,
            "written": written,
            "min_time": min_t if min_t != float("inf") else None,
            "max_time": max_t if max_t != float("-inf") else None,
        }
        logger.info(
            f"  {source}: in_window={in_window:,}, written={written:,}, "
            f"time=[{stats[source]['min_time']}, {stats[source]['max_time']}]"
        )

    # Check time range intersection across all sources
    all_mins = [s["min_time"] for s in stats.values() if s.get("min_time") is not None]
    all_maxs = [s["max_time"] for s in stats.values() if s.get("max_time") is not None]
    if all_mins and all_maxs:
        intersect_start = max(all_mins)
        intersect_end = min(all_maxs)
        if intersect_start <= intersect_end:
            logger.info(
                f"Time intersection across all sources: [{intersect_start}, {intersect_end}] "
                f"({intersect_end - intersect_start}s) - CONFIRMED NON-EMPTY"
            )
        else:
            logger.warning(
                f"Time intersection is EMPTY: [{intersect_start}, {intersect_end}]. "
                f"Auto-widening window by {WINDOW_WIDEN_STEP}s..."
            )
    else:
        logger.warning("Could not compute time intersection (some sources empty)")

    return stats
