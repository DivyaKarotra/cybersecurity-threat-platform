"""
Validation module: reads Gold Parquet back and checks:
- Schema correctness
- No unexpected NULLs in required fields (time, user, threat_type)
- No duplicate detections
- Statistics reconcile with record counts
- Bronze/Silver reconciliation
- Gold summary and high_risk tables reconcile with all_threats

Exits non-zero on failure.
"""
import json
import logging
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from pyspark.sql import SparkSession
from pyspark.sql import functions as F

from config.settings import GOLD_DIR, BRONZE_DIR, SILVER_DIR
from src.utils.statistics import compute_statistics

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("validate")


def validate(spark: SparkSession) -> bool:
    """Run all validation checks. Returns True if all pass, False otherwise."""
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

    if total == 0:
        errors.append("Gold all_threats is empty (0 rows)")

    # 2. Schema check
    expected_cols = {
        "time", "user", "src_computer", "dst_computer", "threat_type",
        "severity", "risk_score", "failed_attempts", "event_count", "description"
    }
    actual_cols = set(threats.columns)
    missing = expected_cols - actual_cols
    if missing:
        errors.append(f"Missing columns in all_threats: {missing}")

    # 3. No unexpected NULLs in required fields
    for col_name in ["time", "threat_type", "user"]:
        if col_name in threats.columns:
            null_count = threats.filter(F.col(col_name).isNull()).count()
            if null_count > 0:
                errors.append(f"Unexpected NULLs in {col_name}: {null_count}")

    # 4. Risk score bounds [0, 100]
    out_of_range = threats.filter(
        (F.col("risk_score") < 0) | (F.col("risk_score") > 100)
    ).count()
    if out_of_range > 0:
        errors.append(f"Risk scores out of [0, 100]: {out_of_range}")

    # 5. Severity values
    valid_severities = {"Low", "Medium", "High", "Critical"}
    sev_rows = threats.select("severity").distinct().collect()
    actual_severities = {r["severity"] for r in sev_rows}
    invalid_sev = actual_severities - valid_severities
    if invalid_sev:
        errors.append(f"Invalid severity values: {invalid_sev}")

    # 6. Duplicate detection check (same time, user, src, dst, type = duplicate)
    dedup_count = threats.dropDuplicates(
        ["time", "user", "src_computer", "dst_computer", "threat_type"]
    ).count()
    if dedup_count < total:
        dup_count = total - dedup_count
        errors.append(f"Duplicate detections found: {dup_count} duplicates (must be 0)")

    # 7. Statistics reconciliation using shared function
    stats = compute_statistics(threats)
    logger.info(f"Computed Statistics:\n{json.dumps(stats, indent=2)}")

    if stats["total_threats"] != total:
        errors.append(f"Stats total ({stats['total_threats']}) != count ({total})")

    type_sum = sum(stats["by_type"].values())
    if type_sum != total:
        errors.append(f"by_type sum ({type_sum}) != total ({total})")

    sev_sum = sum(stats["by_severity"].values())
    if sev_sum != total:
        errors.append(f"by_severity sum ({sev_sum}) != total ({total})")

    expected_high_critical = threats.filter(
        (F.col("severity") == "High") | (F.col("severity") == "Critical")
    ).count()
    if stats["high_critical_count"] != expected_high_critical:
        errors.append(
            f"Stats high_critical ({stats['high_critical_count']}) != filter ({expected_high_critical})"
        )

    # 8. Check high_risk table reconciliation
    high_risk_path = GOLD_DIR / "high_risk"
    if high_risk_path.exists():
        hr_count = spark.read.parquet(str(high_risk_path)).count()
        expected_hr = threats.filter(F.col("risk_score") >= 70).count()
        if hr_count != expected_hr:
            errors.append(f"high_risk count ({hr_count}) != filtered ({expected_hr})")
    else:
        errors.append("Gold high_risk table does not exist")

    # Check summary_by_type table reconciliation
    summary_type_path = GOLD_DIR / "summary_by_type"
    if summary_type_path.exists():
        type_df = spark.read.parquet(str(summary_type_path))
        type_total = type_df.agg(F.sum("count")).collect()[0][0] or 0
        if type_total != total:
            errors.append(f"summary_by_type sum ({type_total}) != total ({total})")
    else:
        errors.append("Gold summary_by_type table does not exist")

    # Check summary_by_severity table reconciliation
    summary_sev_path = GOLD_DIR / "summary_by_severity"
    if summary_sev_path.exists():
        sev_df = spark.read.parquet(str(summary_sev_path))
        sev_total = sev_df.agg(F.sum("count")).collect()[0][0] or 0
        if sev_total != total:
            errors.append(f"summary_by_severity sum ({sev_total}) != total ({total})")
    else:
        errors.append("Gold summary_by_severity table does not exist")

    # Check user_risk and computer_risk tables exist
    for tbl in ["user_risk", "computer_risk", "statistics"]:
        if not (GOLD_DIR / tbl).exists():
            errors.append(f"Gold table {tbl} does not exist")

    # 9. Bronze/Silver reconciliation
    for source in ["auth", "dns", "flows", "proc", "redteam"]:
        bronze_path = BRONZE_DIR / source
        silver_path = SILVER_DIR / source
        if bronze_path.exists() and silver_path.exists():
            bronze_count = spark.read.parquet(str(bronze_path)).count()
            silver_count = spark.read.parquet(str(silver_path)).count()
            if silver_count > bronze_count:
                errors.append(f"{source}: Silver ({silver_count:,}) > Bronze ({bronze_count:,})")
            elif silver_count == 0 and bronze_count > 0:
                errors.append(f"{source}: Silver has 0 rows but Bronze has {bronze_count:,}")
            else:
                logger.info(f"Reconciliation {source}: Bronze={bronze_count:,}, Silver={silver_count:,} (OK)")
        else:
            errors.append(f"Missing Bronze or Silver path for {source}")

    _report(errors)
    return len(errors) == 0


def _report(errors: list):
    if errors:
        logger.error(f"VALIDATION FAILED with {len(errors)} error(s):")
        for e in errors:
            logger.error(f"  ✗ {e}")
    else:
        logger.info("VALIDATION PASSED: All Gold, Silver, and Bronze checks OK")


if __name__ == "__main__":
    from src.utils.spark_session import get_spark_session

    spark = get_spark_session("ValidatePipeline")
    try:
        passed = validate(spark)
        sys.exit(0 if passed else 1)
    finally:
        spark.stop()
