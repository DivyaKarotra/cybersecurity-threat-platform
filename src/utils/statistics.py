"""
Shared statistics module for Cybersecurity Threat Detection Platform.
Used by both the Gold layer summary generation and validate.py.
Computes exact distinct counts and metric summaries.
"""
import logging
from typing import Dict, Any
from pyspark.sql import DataFrame
from pyspark.sql import functions as F

logger = logging.getLogger(__name__)


def compute_statistics(threats: DataFrame) -> Dict[str, Any]:
    """
    ONE shared function computing all statistics from the threats DataFrame.
    Used by both the Gold summary tables and validation routines.

    Returns a dict with exact distinct counts:
      - total_threats: exact total count of threat records
      - unique_users: exact distinct count of non-null users
      - unique_computers: exact distinct count of unique computers unioned across
        src_computer and dst_computer
      - unique_src_computers: exact distinct count of non-null src_computers
      - unique_dst_computers: exact distinct count of non-null dst_computers
      - by_type: exact count mapping per threat_type {threat_type: count}
      - by_severity: exact count mapping per severity {severity: count}
      - high_critical_count: exact count of High and Critical threats
      - avg_risk_score: average risk score across threats (rounded to 2 decimal places)
      - null_counts: dictionary mapping column_name -> null count (only columns with nulls > 0)
    """
    total = threats.count()
    if total == 0:
        return {
            "total_threats": 0,
            "unique_users": 0,
            "unique_computers": 0,
            "unique_src_computers": 0,
            "unique_dst_computers": 0,
            "by_type": {},
            "by_severity": {},
            "high_critical_count": 0,
            "avg_risk_score": 0.0,
            "null_counts": {},
        }

    unique_users = threats.filter(F.col("user").isNotNull()).select("user").distinct().count()
    unique_src_computers = (
        threats.filter(F.col("src_computer").isNotNull()).select("src_computer").distinct().count()
    )
    unique_dst_computers = (
        threats.filter(F.col("dst_computer").isNotNull()).select("dst_computer").distinct().count()
    )

    unique_computers = (
        threats.select(F.col("src_computer").alias("c"))
        .union(threats.select(F.col("dst_computer").alias("c")))
        .filter(F.col("c").isNotNull())
        .distinct()
        .count()
    )

    by_type_rows = threats.groupBy("threat_type").count().collect()
    by_type = {row["threat_type"]: row["count"] for row in by_type_rows}

    by_sev_rows = threats.groupBy("severity").count().collect()
    by_severity = {row["severity"]: row["count"] for row in by_sev_rows}

    high_critical = threats.filter(
        (F.col("severity") == "High") | (F.col("severity") == "Critical")
    ).count()

    avg_risk_val = threats.agg(F.avg("risk_score")).collect()[0][0]
    avg_risk = round(float(avg_risk_val), 2) if avg_risk_val is not None else 0.0

    # NULL counts per field
    null_counts = {}
    for col_name in threats.columns:
        nc = threats.filter(F.col(col_name).isNull()).count()
        if nc > 0:
            null_counts[col_name] = nc

    return {
        "total_threats": total,
        "unique_users": unique_users,
        "unique_computers": unique_computers,
        "unique_src_computers": unique_src_computers,
        "unique_dst_computers": unique_dst_computers,
        "by_type": by_type,
        "by_severity": by_severity,
        "high_critical_count": high_critical,
        "avg_risk_score": avg_risk,
        "null_counts": null_counts,
    }
