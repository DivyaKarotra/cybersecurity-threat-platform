"""
Threat detection rules – each returns a DataFrame with the unified THREAT_SCHEMA:
  time(long), user(str), src_computer(str), dst_computer(str), threat_type(str),
  severity(str), risk_score(int), failed_attempts(long), event_count(long), description(str)

All rules operate on Silver event-level data.
Aggregated rules use first-event time (min time in window).
"""
import logging

from pyspark.sql import SparkSession, DataFrame
from pyspark.sql import functions as F
from pyspark.sql.types import LongType, IntegerType, StringType
from pyspark.sql.window import Window

import config.settings as cfg
from config.settings import (
    SILVER_DIR,
    AUTH_FAIL_THRESHOLD, AUTH_FAIL_WINDOW,
    REDTEAM_FLOW_WINDOW, REDTEAM_DNS_WINDOW, REDTEAM_PROC_WINDOW,
    PROC_STDDEV_MULTIPLIER, PROC_TOP_N_EXCLUDE,
    RISK_BASE, RISK_FAILURE_BONUS_PER, RISK_FAILURE_BONUS_CAP,
    RISK_COUNT_BONUS_PER, RISK_COUNT_BONUS_CAP, RISK_REDTEAM_BONUS,
    SEVERITY_THRESHOLDS,
)

logger = logging.getLogger(__name__)


def compute_risk_score(threat_type: str, failed_attempts: int = 0, event_count: int = 1) -> int:
    """
    Documented risk scoring formula:
      score = base + failure_bonus + count_bonus + redteam_bonus, capped [0, 100]
    Where:
      base = RISK_BASE[threat_type]
      failure_bonus = min(failed_attempts * RISK_FAILURE_BONUS_PER, RISK_FAILURE_BONUS_CAP)
      count_bonus = min((event_count - 1) * RISK_COUNT_BONUS_PER, RISK_COUNT_BONUS_CAP)
      redteam_bonus = RISK_REDTEAM_BONUS if threat_type contains 'redteam'
    """
    base = RISK_BASE.get(threat_type, 30)
    failure_bonus = min(failed_attempts * RISK_FAILURE_BONUS_PER, RISK_FAILURE_BONUS_CAP)
    count_bonus = min(max(event_count - 1, 0) * RISK_COUNT_BONUS_PER, RISK_COUNT_BONUS_CAP)
    redteam_bonus = RISK_REDTEAM_BONUS if "redteam" in threat_type else 0
    return max(0, min(100, base + failure_bonus + count_bonus + redteam_bonus))


def get_severity(risk_score: int) -> str:
    """Map risk_score to severity label."""
    for sev, (lo, hi) in SEVERITY_THRESHOLDS.items():
        if lo <= risk_score <= hi:
            return sev
    return "Low"


def _compute_risk_score_col(threat_type_lit: str):
    """Return a Column expression computing risk_score from failed_attempts and event_count."""
    base = RISK_BASE.get(threat_type_lit, 30)
    has_redteam = 1 if "redteam" in threat_type_lit else 0

    return F.least(
        F.lit(100),
        F.greatest(
            F.lit(0),
            F.lit(base)
            + F.least(
                F.coalesce(F.col("failed_attempts"), F.lit(0)) * F.lit(RISK_FAILURE_BONUS_PER),
                F.lit(RISK_FAILURE_BONUS_CAP)
            )
            + F.least(
                F.greatest(F.coalesce(F.col("event_count"), F.lit(1)) - F.lit(1), F.lit(0)) * F.lit(RISK_COUNT_BONUS_PER),
                F.lit(RISK_COUNT_BONUS_CAP)
            )
            + F.lit(has_redteam * RISK_REDTEAM_BONUS)
        )
    ).cast(IntegerType())


def _severity_col():
    """Return a Column expression mapping risk_score to severity."""
    return (
        F.when(F.col("risk_score") >= 90, F.lit("Critical"))
        .when(F.col("risk_score") >= 70, F.lit("High"))
        .when(F.col("risk_score") >= 40, F.lit("Medium"))
        .otherwise(F.lit("Low"))
    )


def _cast_threat_schema(df: DataFrame) -> DataFrame:
    """Explicitly cast all columns to match THREAT_SCHEMA."""
    return df.select(
        F.col("time").cast(LongType()).alias("time"),
        F.col("user").cast(StringType()).alias("user"),
        F.col("src_computer").cast(StringType()).alias("src_computer"),
        F.col("dst_computer").cast(StringType()).alias("dst_computer"),
        F.col("threat_type").cast(StringType()).alias("threat_type"),
        F.col("severity").cast(StringType()).alias("severity"),
        F.col("risk_score").cast(IntegerType()).alias("risk_score"),
        F.col("failed_attempts").cast(LongType()).alias("failed_attempts"),
        F.col("event_count").cast(LongType()).alias("event_count"),
        F.col("description").cast(StringType()).alias("description"),
    )


def _log_diagnostics(rule_name: str, candidate_count: int, final_count: int):
    logger.info(f"  {rule_name}: candidates={candidate_count:,}, final={final_count:,}")


# ═══════════════════════════════════════════════════════════════════════════
# R1 – Suspicious Authentication (failed logons within sliding window)
# ═══════════════════════════════════════════════════════════════════════════
def rule_suspicious_auth(spark: SparkSession, silver_dir=None) -> DataFrame:
    """
    Group failed logons by (src_user, src_computer, dst_computer) and find
    groups with >= AUTH_FAIL_THRESHOLD failures within AUTH_FAIL_WINDOW seconds.
    Uses tumbling window approximation: floor(time / window_size) as bucket.
    """
    s_dir = silver_dir if silver_dir is not None else cfg.SILVER_DIR
    auth = spark.read.parquet(str(s_dir / "auth"))
    failed = auth.filter(F.col("is_failure") == True)  # noqa: E712

    candidate_count = failed.count()
    logger.info(f"  R1: total failed auth events = {candidate_count:,}")

    if candidate_count == 0:
        logger.info("  R1: No failed auth events found")
        return _empty_threat_df(spark)

    # Tumbling window bucket
    window_size = AUTH_FAIL_WINDOW
    bucketed = failed.withColumn(
        "time_bucket", (F.col("time") / F.lit(window_size)).cast(LongType())
    )

    agg = (
        bucketed
        .groupBy("src_user", "src_computer_key", "dst_computer_key", "time_bucket")
        .agg(
            F.min("time").alias("time"),
            F.count("*").alias("failed_attempts"),
            F.first("src_computer").alias("src_computer_orig"),
            F.first("dst_computer").alias("dst_computer_orig"),
        )
        .filter(F.col("failed_attempts") >= F.lit(AUTH_FAIL_THRESHOLD))
    )

    result = agg.select(
        F.col("time"),
        F.col("src_user").alias("user"),
        F.col("src_computer_orig").alias("src_computer"),
        F.col("dst_computer_orig").alias("dst_computer"),
        F.lit("R1_suspicious_auth").alias("threat_type"),
        F.col("failed_attempts"),
        F.col("failed_attempts").alias("event_count"),
        F.concat(
            F.lit("Suspicious auth: "),
            F.col("failed_attempts").cast(StringType()),
            F.lit(" failed logons from "),
            F.col("src_user"),
            F.lit(" on "),
            F.col("src_computer_orig"),
            F.lit(" → "),
            F.col("dst_computer_orig"),
            F.lit(" within "),
            F.lit(str(window_size)),
            F.lit("s window")
        ).alias("description"),
    )

    result = result.withColumn("risk_score", _compute_risk_score_col("R1_suspicious_auth"))
    result = result.withColumn("severity", _severity_col())
    result = _cast_threat_schema(result)

    final_count = result.count()
    _log_diagnostics("R1_suspicious_auth", candidate_count, final_count)
    return result


# ═══════════════════════════════════════════════════════════════════════════
# R2 – RedTeam + Flow correlation
# ═══════════════════════════════════════════════════════════════════════════
def rule_redteam_flow(spark: SparkSession, silver_dir=None) -> DataFrame:
    """
    Flows where flow.src_computer == redteam.src_computer AND
    flow.dst_computer == redteam.dst_computer AND
    |flow.time - redteam.time| <= REDTEAM_FLOW_WINDOW.
    Dedupe by counting distinct redteam events as detection unit.
    """
    s_dir = silver_dir if silver_dir is not None else cfg.SILVER_DIR
    flows = spark.read.parquet(str(s_dir / "flows")).alias("f")
    redteam = spark.read.parquet(str(s_dir / "redteam")).alias("rt")

    rt_count = redteam.count()
    flow_count = flows.count()
    logger.info(f"  R2: redteam events={rt_count}, flow events={flow_count}")

    if rt_count == 0 or flow_count == 0:
        logger.info("  R2: Empty source data")
        return _empty_threat_df(spark)

    # Key overlap diagnostics
    rt_src_keys = {r[0] for r in redteam.select("src_computer_key").distinct().collect() if r[0] is not None}
    flow_src_keys = {r[0] for r in flows.select("src_computer_key").distinct().collect() if r[0] is not None}
    overlap_src = rt_src_keys & flow_src_keys
    logger.info(f"  R2 diagnostics: RT src_keys={len(rt_src_keys)}, flow src_keys={len(flow_src_keys)}, overlap={len(overlap_src)}")

    if not overlap_src:
        logger.warning("  R2: No key overlap between redteam and flows")
        return _empty_threat_df(spark)

    # Broadcast redteam (small)
    rt_bc = F.broadcast(redteam.select(
        F.col("time").alias("rt_time"),
        F.col("user").alias("rt_user"),
        F.col("src_computer").alias("rt_src_computer"),
        F.col("dst_computer").alias("rt_dst_computer"),
        F.col("src_computer_key").alias("rt_src_key"),
        F.col("dst_computer_key").alias("rt_dst_key"),
    ))

    joined = flows.join(
        rt_bc,
        (F.col("f.src_computer_key") == F.col("rt_src_key")) &
        (F.col("f.dst_computer_key") == F.col("rt_dst_key")) &
        (F.abs(F.col("f.time") - F.col("rt_time")) <= F.lit(REDTEAM_FLOW_WINDOW)),
        "inner"
    )

    candidate_count = joined.count()
    logger.info(f"  R2: raw join matches = {candidate_count}")

    if candidate_count == 0:
        logger.info("  R2: No flow-redteam correlations found within time window")
        return _empty_threat_df(spark)

    # Dedupe: group by (rt_time, rt_src, rt_dst) to count distinct redteam events
    deduped = (
        joined
        .groupBy("rt_time", "rt_src_key", "rt_dst_key")
        .agg(
            F.min(F.col("f.time")).alias("time"),
            F.first("rt_user").alias("user"),
            F.first("rt_src_computer").alias("src_computer"),
            F.first("rt_dst_computer").alias("dst_computer"),
            F.count("*").alias("event_count"),
            F.sum("f.byte_count").alias("total_bytes"),
        )
    )

    result = deduped.select(
        F.col("time"),
        F.col("user"),
        F.col("src_computer"),
        F.col("dst_computer"),
        F.lit("R2_redteam_flow").alias("threat_type"),
        F.lit(0).cast(LongType()).alias("failed_attempts"),
        F.col("event_count"),
        F.concat(
            F.lit("RedTeam-correlated flow: "),
            F.col("src_computer"),
            F.lit(" → "),
            F.col("dst_computer"),
            F.lit(", "),
            F.col("event_count").cast(StringType()),
            F.lit(" flows, "),
            F.coalesce(F.col("total_bytes").cast(StringType()), F.lit("0")),
            F.lit(" bytes total")
        ).alias("description"),
    )

    result = result.withColumn("risk_score", _compute_risk_score_col("R2_redteam_flow"))
    result = result.withColumn("severity", _severity_col())
    result = _cast_threat_schema(result)
    result = result.dropDuplicates(["time", "user", "src_computer", "dst_computer", "threat_type"])

    final_count = result.count()
    _log_diagnostics("R2_redteam_flow", candidate_count, final_count)
    return result


# ═══════════════════════════════════════════════════════════════════════════
# R3 – RedTeam + DNS correlation
# ═══════════════════════════════════════════════════════════════════════════
def rule_redteam_dns(spark: SparkSession, silver_dir=None) -> DataFrame:
    """
    DNS queries where dns.src_computer == redteam.src_computer within time window.
    Description states what resolved_computer is.
    """
    s_dir = silver_dir if silver_dir is not None else cfg.SILVER_DIR
    dns = spark.read.parquet(str(s_dir / "dns")).alias("d")
    redteam = spark.read.parquet(str(s_dir / "redteam")).alias("rt")

    rt_count = redteam.count()
    dns_count = dns.count()
    logger.info(f"  R3: redteam events={rt_count}, dns events={dns_count}")

    if rt_count == 0 or dns_count == 0:
        return _empty_threat_df(spark)

    rt_bc = F.broadcast(redteam.select(
        F.col("time").alias("rt_time"),
        F.col("user").alias("rt_user"),
        F.col("src_computer").alias("rt_src_computer"),
        F.col("dst_computer").alias("rt_dst_computer"),
        F.col("src_computer_key").alias("rt_src_key"),
    ))

    joined = dns.join(
        rt_bc,
        (F.col("d.src_computer_key") == F.col("rt_src_key")) &
        (F.abs(F.col("d.time") - F.col("rt_time")) <= F.lit(REDTEAM_DNS_WINDOW)),
        "inner"
    )

    candidate_count = joined.count()
    logger.info(f"  R3: raw join matches = {candidate_count}")

    if candidate_count == 0:
        # Diagnostics
        rt_src_keys = {r[0] for r in redteam.select("src_computer_key").distinct().collect() if r[0] is not None}
        dns_src_keys = {r[0] for r in dns.select("src_computer_key").distinct().collect() if r[0] is not None}
        logger.info(f"  R3 diagnostics: overlap keys = {len(rt_src_keys & dns_src_keys)}")
        return _empty_threat_df(spark)

    # Group by (rt_time, rt_src, dns resolved target)
    deduped = (
        joined
        .groupBy("rt_time", "rt_src_key")
        .agg(
            F.min(F.col("d.time")).alias("time"),
            F.first("rt_user").alias("user"),
            F.first("rt_src_computer").alias("src_computer"),
            F.first("rt_dst_computer").alias("dst_computer"),
            F.count("*").alias("event_count"),
            F.collect_set("d.resolved_computer").alias("resolved_set"),
        )
    )

    result = deduped.select(
        F.col("time"),
        F.col("user"),
        F.col("src_computer"),
        F.col("dst_computer"),
        F.lit("R3_redteam_dns").alias("threat_type"),
        F.lit(0).cast(LongType()).alias("failed_attempts"),
        F.col("event_count"),
        F.concat(
            F.lit("RedTeam-correlated DNS: "),
            F.col("src_computer"),
            F.lit(" resolved "),
            F.concat_ws(", ", F.col("resolved_set")),
            F.lit(" ("),
            F.col("event_count").cast(StringType()),
            F.lit(" queries near redteam activity)")
        ).alias("description"),
    )

    result = result.withColumn("risk_score", _compute_risk_score_col("R3_redteam_dns"))
    result = result.withColumn("severity", _severity_col())
    result = _cast_threat_schema(result)
    result = result.dropDuplicates(["time", "user", "src_computer", "dst_computer", "threat_type"])

    final_count = result.count()
    _log_diagnostics("R3_redteam_dns", candidate_count, final_count)
    return result


# ═══════════════════════════════════════════════════════════════════════════
# R4 – Suspicious Process (frequency anomaly)
# ═══════════════════════════════════════════════════════════════════════════
def rule_suspicious_process(spark: SparkSession, silver_dir=None) -> DataFrame:
    """
    Per (user, computer, process_name) frequency far above baseline.
    Excludes top-N most widespread processes. Uses mean + N*std threshold.
    """
    s_dir = silver_dir if silver_dir is not None else cfg.SILVER_DIR
    proc = spark.read.parquet(str(s_dir / "proc"))
    proc_count = proc.count()
    logger.info(f"  R4: proc events={proc_count}")

    if proc_count == 0:
        return _empty_threat_df(spark)

    # Find widespread processes (by max computer share or top-N)
    max_share = getattr(cfg, "PROC_MAX_COMPUTER_SHARE", None)
    top_n = getattr(cfg, "PROC_TOP_N_EXCLUDE", PROC_TOP_N_EXCLUDE)

    if max_share is not None and max_share > 0:
        total_comps = proc.select("computer_key").distinct().count()
        process_spread = (
            proc.groupBy("process_name")
            .agg(F.countDistinct("computer_key").alias("distinct_computers"))
            .filter(F.col("distinct_computers") > F.lit(total_comps * max_share))
        )
        excluded_processes = {
            r[0] for r in process_spread.select("process_name").collect() if r[0] is not None
        }
    elif top_n > 0:
        process_spread = (
            proc.groupBy("process_name")
            .agg(F.countDistinct("computer_key").alias("distinct_computers"))
            .orderBy(F.desc("distinct_computers"))
            .limit(top_n)
        )
        excluded_processes = {
            r[0] for r in process_spread.select("process_name").collect() if r[0] is not None
        }
    else:
        excluded_processes = set()
    logger.info(f"  R4: excluding {len(excluded_processes)} widespread processes")

    # Filter out excluded processes if any
    if excluded_processes:
        proc_filtered = proc.filter(~F.col("process_name").isin(list(excluded_processes)))
    else:
        proc_filtered = proc

    # Per (computer, process_name) frequency
    freq = (
        proc_filtered
        .groupBy("computer_key", "process_name")
        .agg(F.count("*").alias("proc_count"))
    )

    # Stats per process_name across computers
    stats = (
        freq.groupBy("process_name")
        .agg(
            F.mean("proc_count").alias("mean_count"),
            F.stddev("proc_count").alias("std_count"),
        )
        .withColumn("std_count", F.coalesce(F.col("std_count"), F.lit(0.0)))
    )

    # Per (user, computer, process) counts
    user_proc = (
        proc_filtered
        .groupBy("user", "computer_key", "process_name")
        .agg(
            F.count("*").alias("user_proc_count"),
            F.min("time").alias("time"),
            F.first("computer").alias("computer_orig"),
        )
    )

    # Join with stats to find anomalies
    std_mult = getattr(cfg, "PROC_STDDEV_MULTIPLIER", PROC_STDDEV_MULTIPLIER)
    min_count = getattr(cfg, "PROC_MIN_ANOMALY_COUNT", 1)

    cond = F.col("up.user_proc_count") > (
        F.col("s.mean_count") + F.lit(std_mult) * F.col("s.std_count")
    )
    if min_count > 1:
        cond = cond & (F.col("up.user_proc_count") >= F.lit(min_count))

    anomalies = (
        user_proc.alias("up")
        .join(stats.alias("s"), "process_name", "left")
        .filter(cond)
    )

    candidate_count = anomalies.count()
    logger.info(f"  R4: anomaly candidates = {candidate_count}")

    if candidate_count == 0:
        return _empty_threat_df(spark)

    result = anomalies.select(
        F.col("up.time").alias("time"),
        F.col("up.user").alias("user"),
        F.col("up.computer_orig").alias("src_computer"),
        F.lit(None).cast(StringType()).alias("dst_computer"),
        F.lit("R4_suspicious_process").alias("threat_type"),
        F.lit(0).cast(LongType()).alias("failed_attempts"),
        F.col("up.user_proc_count").alias("event_count"),
        F.concat(
            F.lit("Suspicious process frequency: "),
            F.col("up.process_name"),
            F.lit(" by "),
            F.col("up.user"),
            F.lit(" on "),
            F.col("up.computer_orig"),
            F.lit(" (count="),
            F.col("up.user_proc_count").cast(StringType()),
            F.lit(", baseline mean="),
            F.round(F.col("s.mean_count"), 1).cast(StringType()),
            F.lit(", std="),
            F.round(F.col("s.std_count"), 1).cast(StringType()),
            F.lit(")")
        ).alias("description"),
    )

    result = result.withColumn("risk_score", _compute_risk_score_col("R4_suspicious_process"))
    result = result.withColumn("severity", _severity_col())
    result = _cast_threat_schema(result)

    final_count = result.count()
    _log_diagnostics("R4_suspicious_process", candidate_count, final_count)
    return result


# ═══════════════════════════════════════════════════════════════════════════
# R5 – RedTeam + Process correlation
# ═══════════════════════════════════════════════════════════════════════════
def rule_redteam_process(spark: SparkSession, silver_dir=None) -> DataFrame:
    """
    proc.user_key == redteam.user_key AND proc.computer_key == redteam.src_computer_key
    within time window.
    """
    s_dir = silver_dir if silver_dir is not None else cfg.SILVER_DIR
    proc = spark.read.parquet(str(s_dir / "proc")).alias("p")
    redteam = spark.read.parquet(str(s_dir / "redteam")).alias("rt")

    rt_count = redteam.count()
    proc_count = proc.count()
    logger.info(f"  R5: redteam events={rt_count}, proc events={proc_count}")

    if rt_count == 0 or proc_count == 0:
        return _empty_threat_df(spark)

    rt_bc = F.broadcast(redteam.select(
        F.col("time").alias("rt_time"),
        F.col("user").alias("rt_user"),
        F.col("src_computer").alias("rt_src_computer"),
        F.col("dst_computer").alias("rt_dst_computer"),
        F.col("user_key").alias("rt_user_key"),
        F.col("src_computer_key").alias("rt_src_key"),
    ))

    joined = proc.join(
        rt_bc,
        (F.col("p.user_key") == F.col("rt_user_key")) &
        (F.col("p.computer_key") == F.col("rt_src_key")) &
        (F.abs(F.col("p.time") - F.col("rt_time")) <= F.lit(REDTEAM_PROC_WINDOW)),
        "inner"
    )

    candidate_count = joined.count()
    logger.info(f"  R5: raw join matches = {candidate_count}")

    if candidate_count == 0:
        # Diagnostics
        rt_user_keys = {r[0] for r in redteam.select("user_key").distinct().collect() if r[0] is not None}
        proc_user_keys = {r[0] for r in proc.select("user_key").distinct().collect() if r[0] is not None}
        rt_src_keys = {r[0] for r in redteam.select("src_computer_key").distinct().collect() if r[0] is not None}
        proc_comp_keys = {r[0] for r in proc.select("computer_key").distinct().collect() if r[0] is not None}
        logger.info(f"  R5 diagnostics: user overlap={len(rt_user_keys & proc_user_keys)}, "
                     f"computer overlap={len(rt_src_keys & proc_comp_keys)}")
        return _empty_threat_df(spark)

    deduped = (
        joined
        .groupBy("rt_time", "rt_user_key", "rt_src_key")
        .agg(
            F.min(F.col("p.time")).alias("time"),
            F.first("rt_user").alias("user"),
            F.first("rt_src_computer").alias("src_computer"),
            F.first("rt_dst_computer").alias("dst_computer"),
            F.count("*").alias("event_count"),
            F.collect_set("p.process_name").alias("processes"),
        )
    )

    result = deduped.select(
        F.col("time"),
        F.col("user"),
        F.col("src_computer"),
        F.col("dst_computer"),
        F.lit("R5_redteam_process").alias("threat_type"),
        F.lit(0).cast(LongType()).alias("failed_attempts"),
        F.col("event_count"),
        F.concat(
            F.lit("RedTeam-correlated processes: "),
            F.concat_ws(", ", F.col("processes")),
            F.lit(" by "),
            F.col("user"),
            F.lit(" on "),
            F.col("src_computer")
        ).alias("description"),
    )

    result = result.withColumn("risk_score", _compute_risk_score_col("R5_redteam_process"))
    result = result.withColumn("severity", _severity_col())
    result = _cast_threat_schema(result)
    result = result.dropDuplicates(["time", "user", "src_computer", "dst_computer", "threat_type"])

    final_count = result.count()
    _log_diagnostics("R5_redteam_process", candidate_count, final_count)
    return result


def _empty_threat_df(spark: SparkSession) -> DataFrame:
    """Return an empty DataFrame with THREAT_SCHEMA using emptyRDD to avoid Python worker issues."""
    from src.utils.schemas import THREAT_SCHEMA
    return spark.createDataFrame(spark.sparkContext.emptyRDD(), schema=THREAT_SCHEMA)


def _empty_threat_schema(spark: SparkSession) -> "StructType":
    """Return the threat schema for empty DataFrames."""
    from src.utils.schemas import THREAT_SCHEMA
    return THREAT_SCHEMA


def combine_threats(spark: SparkSession, *dfs: DataFrame) -> DataFrame:
    """
    Union all threat DataFrames using unionByName, cast explicitly to THREAT_SCHEMA.
    Checks and logs:
      - Unexpected NULLs in time, user, threat_type (must be 0)
      - Duplicate detections (must be 0)
    """
    combined = None
    for df in dfs:
        if df is None:
            continue
        df = _cast_threat_schema(df)
        if combined is None:
            combined = df
        else:
            combined = combined.unionByName(df)

    if combined is None:
        return _empty_threat_df(spark)

    # Check for duplicate detections
    initial_count = combined.count()
    distinct_count = combined.distinct().count()
    dup_count = initial_count - distinct_count
    logger.info(f"Duplicate detections: {dup_count}")
    if dup_count > 0:
        logger.warning(f"Deduplicating {dup_count} duplicate detections from combined threats")
        combined = combined.distinct()

    # Re-verify duplicate detections is exactly 0
    final_dup_count = combined.count() - combined.distinct().count()
    logger.info(f"Final duplicate detections check: {final_dup_count}")
    if final_dup_count > 0:
        raise ValueError(
            f"Duplicate detections after deduplication must be 0, got {final_dup_count}"
        )

    # Validate no unexpected NULLs in required fields (time, user, threat_type)
    null_time = combined.filter(F.col("time").isNull()).count()
    null_user = combined.filter(F.col("user").isNull()).count()
    null_type = combined.filter(F.col("threat_type").isNull()).count()
    logger.info(
        f"Unexpected NULLs check: time={null_time}, user={null_user}, threat_type={null_type}"
    )
    if null_time > 0 or null_user > 0 or null_type > 0:
        raise ValueError(
            f"Unexpected NULLs in combined threats: time={null_time}, user={null_user}, threat_type={null_type}"
        )

    logger.info(f"Combined threats: {combined.count():,} total rows")
    return combined
