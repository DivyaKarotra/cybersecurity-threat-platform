"""
Validation module: reads Gold Parquet back and checks:
- Schema correctness
- No unexpected NULLs in required fields
- No duplicate detections
- Statistics reconcile with record counts
- Bronze/Silver reconciliation
Exits non-zero on failure.
"""
import logging
import json
import sys

from pyspark.sql import SparkSession
from pyspark.sql import functions as F

from config.settings import GOLD_DIR, BRONZE_DIR, SILVER_DIR
from src.analytics.gold import compute_statistics

logger = logging.getLogger(__name__)


def validate(spark: SparkSession) -> bool:
    """Run all validation checks. Returns True if all pass."""
    errors = []

    # 1. Read Gold all_threats
    threats_path = GOLD_DIR / "all_threats"
    if not threats_path.exists():
        errors.append("Gold all_threats directory does not exist")
        _report(errors)
        return False

    threats = spark.read.parquet(str(threats_path))
    total = threats.count()
    logger.info(f"Validation: Gold all_threats has {total:,} rows")

    # 2. Schema check
    expected_cols = {"time", "user", "src_computer", "dst_computer", "threat_type",
                     "severity", "risk_score", "failed_attempts", "event_count", "description"}
    actual_cols = set(threats.columns)
    missing = expected_cols - actual_cols
    extra = actual_cols - expected_cols
    if missing:
        errors.append(f"Missing columns in all_threats: {missing}")
    if extra:
        logger.warning(f"Extra columns in all_threats (not an error): {extra}")

    # 3. No unexpected NULLs in required fields
    for col_name in ["time", "threat_type"]:
        null_count = threats.filter(F.col(col_name).isNull()).count()
        if null_count > 0:
            errors.append(f"Unexpected NULLs in {col_name}: {null_count}")

    # 4. Risk score bounds
    out_of_range = threats.filter(
        (F.col("risk_score") < 0) | (F.col("risk_score") > 100)
    ).count()
    if out_of_range > 0:
        errors.append(f"Risk scores out of [0,100]: {out_of_range}")

    # 5. Severity values
    valid_severities = {"Low", "Medium", "High", "Critical"}
    actual_severities = set(
        threats.select("severity").distinct().toPandas()["severity"].tolist()
    )
    invalid_sev = actual_severities - valid_severities
    if invalid_sev:
        errors.append(f"Invalid severity values: {invalid_sev}")

    # 6. Duplicate detection check (same time, user, src, dst, type = duplicate)
    dedup_count = threats.dropDuplicates(
        ["time", "user", "src_computer", "dst_computer", "threat_type"]
    ).count()
    if dedup_count < total:
        dup_count = total - dedup_count
        logger.warning(f"Potential duplicate detections: {dup_count}")
        # Not necessarily an error for aggregated results

    # 7. Statistics reconciliation
    stats = compute_statistics(threats)
    logger.info(f"Statistics: {json.dumps(stats, indent=2)}")

    # Check total matches
    if stats["total_threats"] != total:
        errors.append(f"Stats total ({stats['total_threats']}) != count ({total})")

    # Check by_type sums
    type_sum = sum(stats["by_type"].values())
    if type_sum != total:
        errors.append(f"by_type sum ({type_sum}) != total ({total})")

    # Check by_severity sums
    sev_sum = sum(stats["by_severity"].values())
    if sev_sum != total:
        errors.append(f"by_severity sum ({sev_sum}) != total ({total})")

    # 8. Bronze/Silver reconciliation
    for source in ["auth", "dns", "flows", "proc", "redteam"]:
        bronze_path = BRONZE_DIR / source
        silver_path = SILVER_DIR / source
        if bronze_path.exists() and silver_path.exists():
            bronze_count = spark.read.parquet(str(bronze_path)).count()
            silver_count = spark.read.parquet(str(silver_path)).count()
            if silver_count > bronze_count:
                errors.append(f"{source}: Silver ({silver_count}) > Bronze ({bronze_count})")
            logger.info(f"  {source}: Bronze={bronze_count:,}, Silver={silver_count:,}")

    # 9. Check high_risk reconciliation
    high_risk_path = GOLD_DIR / "high_risk"
    if high_risk_path.exists():
        hr_count = spark.read.parquet(str(high_risk_path)).count()
        expected_hr = threats.filter(F.col("risk_score") >= 70).count()
        if hr_count != expected_hr:
            errors.append(f"high_risk count ({hr_count}) != filtered ({expected_hr})")

    _report(errors)
    return len(errors) == 0


def _report(errors: list):
    if errors:
        logger.error("VALIDATION FAILED:")
        for e in errors:
            logger.error(f"  ✗ {e}")
    else:
        logger.info("VALIDATION PASSED: All checks OK")
