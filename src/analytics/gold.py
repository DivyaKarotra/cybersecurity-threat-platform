"""
Gold layer: final analytics tables written as Parquet.
- all_threats: unified threat detections
- summary_by_type, summary_by_severity
- high_risk: threats with risk_score >= 70
- statistics: aggregate stats
- user_risk, computer_risk: risk profiles
- Per-source analytics: flow_analytics, auth_analytics, dns_analytics,
  process_analytics, redteam_description
All statistics computed from the final Gold threats table via compute_statistics().
"""
import logging

from pyspark.sql import SparkSession, DataFrame
from pyspark.sql import functions as F
from pyspark.sql.types import LongType, IntegerType, StringType

from config.settings import GOLD_DIR, SILVER_DIR, HIGH_VOLUME_FLOW_THRESHOLD

logger = logging.getLogger(__name__)


def compute_statistics(threats: DataFrame) -> dict:
    """
    ONE shared function computing all statistics from the threats DataFrame.
    Used by both the summary tables and validation.
    Returns a dict with exact distinct counts.
    """
    total = threats.count()
    if total == 0:
        return {
            "total_threats": 0,
            "unique_users": 0,
            "unique_computers": 0,
            "by_type": {},
            "by_severity": {},
            "high_critical_count": 0,
            "avg_risk_score": 0.0,
            "null_counts": {},
        }

    unique_users = threats.select("user").distinct().count()
    unique_src_computers = threats.select("src_computer").distinct().count()
    unique_dst_computers = threats.select("dst_computer").distinct().count()
    unique_computers = (
        threats.select(F.col("src_computer").alias("c"))
        .union(threats.select(F.col("dst_computer").alias("c")))
        .filter(F.col("c").isNotNull())
        .distinct()
        .count()
    )

    by_type = dict(
        threats.groupBy("threat_type").count()
        .toPandas().set_index("threat_type")["count"].to_dict()
    )

    by_severity = dict(
        threats.groupBy("severity").count()
        .toPandas().set_index("severity")["count"].to_dict()
    )

    high_critical = threats.filter(
        (F.col("severity") == "High") | (F.col("severity") == "Critical")
    ).count()

    avg_risk = threats.agg(F.avg("risk_score")).collect()[0][0] or 0.0

    # NULL counts per field
    columns = threats.columns
    null_counts = {}
    for col_name in columns:
        nc = threats.filter(F.col(col_name).isNull()).count()
        if nc > 0:
            null_counts[col_name] = nc

    return {
        "total_threats": total,
        "unique_users": unique_users,
        "unique_computers": unique_computers,
        "by_type": by_type,
        "by_severity": by_severity,
        "high_critical_count": high_critical,
        "avg_risk_score": round(avg_risk, 2),
        "null_counts": null_counts,
    }


def write_gold(spark: SparkSession, threats: DataFrame) -> dict:
    """Write all Gold tables. Returns statistics dict."""
    GOLD_DIR.mkdir(parents=True, exist_ok=True)

    # 1. All threats
    threats.write.mode("overwrite").parquet(str(GOLD_DIR / "all_threats"))
    total = threats.count()
    logger.info(f"Gold all_threats: {total:,} rows")

    # 2. Statistics (computed once, used everywhere)
    stats = compute_statistics(threats)

    # 3. Summary by type
    by_type = threats.groupBy("threat_type").agg(
        F.count("*").alias("count"),
        F.avg("risk_score").alias("avg_risk"),
        F.min("risk_score").alias("min_risk"),
        F.max("risk_score").alias("max_risk"),
        F.sum("event_count").alias("total_events"),
    )
    by_type.write.mode("overwrite").parquet(str(GOLD_DIR / "summary_by_type"))

    # 4. Summary by severity
    by_sev = threats.groupBy("severity").agg(
        F.count("*").alias("count"),
        F.avg("risk_score").alias("avg_risk"),
    )
    by_sev.write.mode("overwrite").parquet(str(GOLD_DIR / "summary_by_severity"))

    # 5. High risk threats (>= 70)
    high_risk = threats.filter(F.col("risk_score") >= 70)
    high_risk.write.mode("overwrite").parquet(str(GOLD_DIR / "high_risk"))
    logger.info(f"Gold high_risk: {high_risk.count():,} rows")

    # 6. Statistics as Parquet (single row)
    import json
    stats_rows = [{"stats_json": json.dumps(stats)}]
    stats_df = spark.createDataFrame(stats_rows)
    stats_df.write.mode("overwrite").parquet(str(GOLD_DIR / "statistics"))

    # 7. User risk profile
    user_risk = threats.groupBy("user").agg(
        F.count("*").alias("threat_count"),
        F.avg("risk_score").alias("avg_risk"),
        F.max("risk_score").alias("max_risk"),
        F.collect_set("threat_type").alias("threat_types"),
        F.sum("event_count").alias("total_events"),
    ).orderBy(F.desc("max_risk"))
    user_risk.write.mode("overwrite").parquet(str(GOLD_DIR / "user_risk"))

    # 8. Computer risk profile
    computer_risk = (
        threats.select(
            F.col("src_computer").alias("computer"),
            F.col("risk_score"),
            F.col("threat_type"),
            F.col("event_count"),
        )
        .union(
            threats.select(
                F.col("dst_computer").alias("computer"),
                F.col("risk_score"),
                F.col("threat_type"),
                F.col("event_count"),
            )
        )
        .filter(F.col("computer").isNotNull())
        .groupBy("computer")
        .agg(
            F.count("*").alias("threat_count"),
            F.avg("risk_score").alias("avg_risk"),
            F.max("risk_score").alias("max_risk"),
            F.collect_set("threat_type").alias("threat_types"),
            F.sum("event_count").alias("total_events"),
        )
        .orderBy(F.desc("max_risk"))
    )
    computer_risk.write.mode("overwrite").parquet(str(GOLD_DIR / "computer_risk"))

    # 9. Per-source analytics
    _write_source_analytics(spark)

    return stats


def _write_source_analytics(spark: SparkSession):
    """Write per-source analytics from Silver data."""
    # Flow analytics
    try:
        flows = spark.read.parquet(str(SILVER_DIR / "flows"))
        flow_stats = flows.agg(
            F.count("*").alias("total_flows"),
            F.sum("packet_count").alias("total_packets"),
            F.sum("byte_count").alias("total_bytes"),
            F.avg("byte_count").alias("avg_bytes"),
            F.avg("duration").alias("avg_duration"),
        )
        flow_stats.write.mode("overwrite").parquet(str(GOLD_DIR / "flow_totals"))

        # By protocol
        flow_by_proto = flows.groupBy("protocol").agg(
            F.count("*").alias("count"),
            F.sum("byte_count").alias("total_bytes"),
            F.sum("packet_count").alias("total_packets"),
        )
        flow_by_proto.write.mode("overwrite").parquet(str(GOLD_DIR / "flow_by_protocol"))

        # Top pairs
        flow_top_pairs = (
            flows.groupBy("src_computer", "dst_computer")
            .agg(
                F.count("*").alias("flow_count"),
                F.sum("byte_count").alias("total_bytes"),
            )
            .orderBy(F.desc("total_bytes"))
            .limit(100)
        )
        flow_top_pairs.write.mode("overwrite").parquet(str(GOLD_DIR / "flow_top_pairs"))

        # High volume
        high_vol = flows.filter(F.col("byte_count") > F.lit(HIGH_VOLUME_FLOW_THRESHOLD))
        high_vol.write.mode("overwrite").parquet(str(GOLD_DIR / "flow_high_volume"))
        logger.info(f"Flow analytics written")
    except Exception as e:
        logger.warning(f"Flow analytics skipped: {e}")

    # Auth analytics
    try:
        auth = spark.read.parquet(str(SILVER_DIR / "auth"))
        auth_summary = auth.groupBy("success_failure").agg(
            F.count("*").alias("count")
        )
        auth_summary.write.mode("overwrite").parquet(str(GOLD_DIR / "auth_summary"))

        auth_by_type = auth.groupBy("auth_type", "logon_type").agg(
            F.count("*").alias("count")
        )
        auth_by_type.write.mode("overwrite").parquet(str(GOLD_DIR / "auth_by_type"))
        logger.info("Auth analytics written")
    except Exception as e:
        logger.warning(f"Auth analytics skipped: {e}")

    # DNS analytics
    try:
        dns = spark.read.parquet(str(SILVER_DIR / "dns"))
        dns_summary = dns.groupBy("src_computer").agg(
            F.count("*").alias("query_count"),
            F.countDistinct("resolved_computer").alias("unique_resolved"),
        ).orderBy(F.desc("query_count")).limit(100)
        dns_summary.write.mode("overwrite").parquet(str(GOLD_DIR / "dns_summary"))
        logger.info("DNS analytics written")
    except Exception as e:
        logger.warning(f"DNS analytics skipped: {e}")

    # Process analytics
    try:
        proc = spark.read.parquet(str(SILVER_DIR / "proc"))
        proc_summary = proc.groupBy("process_name").agg(
            F.count("*").alias("count"),
            F.countDistinct("computer").alias("unique_computers"),
            F.countDistinct("user").alias("unique_users"),
        ).orderBy(F.desc("count")).limit(100)
        proc_summary.write.mode("overwrite").parquet(str(GOLD_DIR / "process_summary"))
        logger.info("Process analytics written")
    except Exception as e:
        logger.warning(f"Process analytics skipped: {e}")

    # Redteam description
    try:
        rt = spark.read.parquet(str(SILVER_DIR / "redteam"))
        rt_desc = rt.select(
            "time", "user", "src_computer", "dst_computer"
        ).orderBy("time")
        rt_desc.write.mode("overwrite").parquet(str(GOLD_DIR / "redteam_description"))
        logger.info("Redteam description written")
    except Exception as e:
        logger.warning(f"Redteam description skipped: {e}")
