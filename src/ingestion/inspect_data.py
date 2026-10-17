"""
Inspection stage: streams .gz files to collect head-5 rows and verify schema.
For large files, reads only INSPECT_LIMIT rows for speed.
For small files (redteam), reads fully. Min time from first row (data is time-sorted).
Saves results to config/schema_reference.json.
"""
import gzip
import json
import logging

from config.settings import RAW_FILES, SCHEMA_REF

logger = logging.getLogger(__name__)

# Only read this many rows per large file for inspection
INSPECT_LIMIT = 10_000


def inspect_sources() -> dict:
    """Stream each .gz source, collect head-5 and schema info."""
    results = {}
    for source, path in RAW_FILES.items():
        logger.info(f"Inspecting {source} from {path}")
        if not path.exists():
            logger.warning(f"  File not found: {path}")
            results[source] = {"error": "file not found"}
            continue

        head_rows = []
        min_time = float("inf")
        max_time = float("-inf")
        row_count = 0

        # Small files: read fully. Large files: read INSPECT_LIMIT rows.
        is_small = path.stat().st_size < 10_000_000  # < 10MB
        limit = None if is_small else INSPECT_LIMIT

        with gzip.open(str(path), "rt", encoding="utf-8", errors="replace") as f:
            for line in f:
                row_count += 1
                line = line.strip()
                if not line:
                    continue
                if len(head_rows) < 5:
                    head_rows.append(line)

                parts = line.split(",", 1)
                try:
                    t = int(parts[0])
                    if t < min_time:
                        min_time = t
                    if t > max_time:
                        max_time = t
                except (ValueError, IndexError):
                    pass

                if limit and row_count >= limit:
                    break

        col_count = len(head_rows[0].split(",")) if head_rows else 0
        results[source] = {
            "rows_inspected": row_count,
            "full_scan": is_small,
            "col_count": col_count,
            "min_time": min_time if min_time != float("inf") else None,
            "max_time": max_time if max_time != float("-inf") else None,
            "head_5": head_rows,
        }
        logger.info(
            f"  {source}: inspected {row_count:,} rows, {col_count} cols, "
            f"time=[{results[source]['min_time']}, {results[source]['max_time']}]"
            f"{' (partial)' if not is_small else ' (full)'}"
        )

    # Save
    SCHEMA_REF.parent.mkdir(parents=True, exist_ok=True)
    with open(str(SCHEMA_REF), "w") as f:
        json.dump(results, f, indent=2)
    logger.info(f"Schema reference saved to {SCHEMA_REF}")
    return results
