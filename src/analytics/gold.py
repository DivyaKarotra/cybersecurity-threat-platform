"""
Gold layer: final analytics tables written as Parquet.
- all_threats / threats/all_threats: unified threat detections
- summary_by_type / summary/by_type, summary_by_severity / summary/by_severity
- high_risk: threats with risk_score >= 70
- statistics: aggregate stats
- user_risk, computer_risk: risk profiles
- Per-source analytics: flow_totals, flow_by_protocol, flow_top_pairs,
  flow_high_volume, auth_summary, auth_by_type, dns_summary,
  process_summary, redteam_description

All statistics computed from the final Gold threats table via compute_statistics()
from src.utils.statistics.
"""
import json
import logging
import shutil
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq
from pyspark.sql import SparkSession, DataFrame
from pyspark.sql import functions as F

from config.settings import GOLD_DIR, SILVER_DIR, HIGH_VOLUME_FLOW_THRESHOLD
from src.utils.statistics import compute_statistics

logger = logging.getLogger(__name__)


def write_gold(spark: SparkSession, threats: DataFrame) -> dict:
    """Write all Gold tables. Returns statistics dict."""
    GOLD_DIR.mkdir(parents=True, exist_ok=True)
    (GOLD_DIR / "threats").mkdir(parents=True, exist_ok=True)
    (GOLD_DIR / "summary").mkdir(parents=True, exist_ok=True)

    # Materialize and cache in memory to prevent self-referencing lazy reads on overwrite
    threats = threats.dropDuplicates(
        ["time", "user", "src_computer", "dst_computer", "threat_type"]
    ).cache()
    total = threats.count()
    logger.info(f"Gold all_threats cached: {total:,} rows")

    # 1. All threats (both all_threats and threats/all_threats)
    threats.write.mode("overwrite").parquet(str(GOLD_DIR / "all_threats"))
    threats.write.mode("overwrite").parquet(str(GOLD_DIR / "threats" / "all_threats"))
    logger.info(f"Gold all_threats written: {total:,} rows")

    # 2. Statistics (computed once via shared function, used everywhere)
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
    by_type.write.mode("overwrite").parquet(str(GOLD_DIR / "summary" / "by_type"))

    # 4. Summary by severity
    by_sev = threats.groupBy("severity").agg(
        F.count("*").alias("count"),
        F.avg("risk_score").alias("avg_risk"),
        F.min("risk_score").alias("min_risk"),
        F.max("risk_score").alias("max_risk"),
        F.sum("event_count").alias("total_events"),
    )
    by_sev.write.mode("overwrite").parquet(str(GOLD_DIR / "summary_by_severity"))
    by_sev.write.mode("overwrite").parquet(str(GOLD_DIR / "summary" / "by_severity"))

    # 5. High risk threats (>= 70)
    high_risk = threats.filter(F.col("risk_score") >= 70)
    high_risk.write.mode("overwrite").parquet(str(GOLD_DIR / "high_risk"))
    logger.info(f"Gold high_risk: {high_risk.count():,} rows")

    # 6. Statistics as Parquet (written via pyarrow to avoid Windows Py3.13 PySpark socket issue)
    stats_dir = GOLD_DIR / "statistics"
    if stats_dir.exists():
        shutil.rmtree(stats_dir)
    stats_dir.mkdir(parents=True, exist_ok=True)
    table = pa.Table.from_pydict({"stats_json": [json.dumps(stats)]})
    pq.write_table(table, str(stats_dir / "part-0.parquet"))
    logger.info("Gold statistics written")

    # 7. User risk profile
    user_risk = threats.groupBy("user").agg(
        F.count("*").alias("threat_count"),
        F.avg("risk_score").alias("avg_risk"),
        F.max("risk_score").alias("max_risk"),
        F.collect_set("threat_type").alias("threat_types"),
        F.sum("event_count").alias("total_events"),
    ).orderBy(F.desc("max_risk"))
    user_risk.write.mode("overwrite").parquet(str(GOLD_DIR / "user_risk"))
    logger.info("Gold user_risk written")

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
    logger.info("Gold computer_risk written")

    # 9. Per-source analytics
    write_source_analytics(spark)

    return stats


def write_source_analytics(spark: SparkSession):
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
        logger.info("Flow analytics written")
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


if __name__ == "__main__":
    import argparse
    from src.utils.spark_session import get_spark_session
    parser = argparse.ArgumentParser(description="Run Gold layer.")
    parser.add_argument("--source-analytics-only", action="store_true", help="Run only per-source analytics")
    args = parser.parse_args()

    spark = get_spark_session("GoldStage")
    if args.source_analytics_only:
        write_source_analytics(spark)
    else:
        from config.settings import GOLD_DIR
        threats_path = GOLD_DIR / "all_threats"
        has_parquet = threats_path.exists() and any(threats_path.glob("*.parquet"))
        if has_parquet:
            threats = spark.read.parquet(str(threats_path))
            write_gold(spark, threats)
        else:
            logger.info("Running rules and combine to prepare threats...")
            from src.analytics.threat_rules import (
                rule_suspicious_auth, rule_redteam_flow, rule_redteam_dns,
                rule_suspicious_process, rule_redteam_process, combine_threats
            )
            r1 = rule_suspicious_auth(spark)
            r2 = rule_redteam_flow(spark)
            r3 = rule_redteam_dns(spark)
            r4 = rule_suspicious_process(spark)
            r5 = rule_redteam_process(spark)
            combined = combine_threats(spark, r1, r2, r3, r4, r5)
            write_gold(spark, combined)
    spark.stop()
