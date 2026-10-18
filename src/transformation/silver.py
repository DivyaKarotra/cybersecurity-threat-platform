"""
Silver layer: standardised snake_case, correct types, normalised join keys,
drop only malformed rows (null time/key fields), log dropped counts.
Keep original identifiers; add upper-case trimmed join keys.
"""
import logging

from pyspark.sql import SparkSession, DataFrame
from pyspark.sql import functions as F
from pyspark.sql.types import BooleanType

from config.settings import BRONZE_DIR, SILVER_DIR

logger = logging.getLogger(__name__)


def _add_join_keys(df: DataFrame, computer_cols: list, user_cols: list) -> DataFrame:
    """Add normalised upper-case trimmed join keys for computers and users."""
    for col in computer_cols:
        key_name = f"{col}_key"
        df = df.withColumn(key_name, F.upper(F.trim(F.col(col))))
    for col in user_cols:
        key_name = f"{col}_key"
        df = df.withColumn(key_name, F.upper(F.trim(F.col(col))))
    return df


def _reconcile(source: str, bronze_count: int, kept: int, dropped: int):
    """Validate kept + dropped == bronze_count."""
    if kept + dropped != bronze_count:
        logger.error(
            f"RECONCILIATION FAILURE {source}: kept({kept}) + dropped({dropped}) "
            f"!= bronze({bronze_count})"
        )
        raise RuntimeError(f"Bronze→Silver reconciliation failed for {source}")
    logger.info(f"  {source} reconcile OK: {kept} kept + {dropped} dropped = {bronze_count}")


def transform_auth(spark: SparkSession) -> int:
    """Silver auth: add is_failure bool, join keys, drop nulls in key fields."""
    bronze_path = BRONZE_DIR / "auth"
    df = spark.read.parquet(str(bronze_path))
    bronze_count = df.count()

    df = df.withColumn("is_failure", F.col("success_failure") == F.lit("Fail"))
    df = _add_join_keys(df,
                        computer_cols=["src_computer", "dst_computer"],
                        user_cols=["src_user", "dst_user"])

    # Drop malformed: null time or null key fields
    valid = df.filter(
        F.col("time").isNotNull() &
        F.col("src_computer_key").isNotNull() &
        F.col("src_user_key").isNotNull()
    )
    kept = valid.count()
    dropped = bronze_count - kept
    logger.info(f"  auth: kept={kept:,}, dropped={dropped:,}")
    _reconcile("auth", bronze_count, kept, dropped)

    out_path = SILVER_DIR / "auth"
    valid.write.mode("overwrite").parquet(str(out_path))
    return kept


def transform_dns(spark: SparkSession) -> int:
    """Silver dns: join keys, drop nulls."""
    bronze_path = BRONZE_DIR / "dns"
    df = spark.read.parquet(str(bronze_path))
    bronze_count = df.count()

    df = _add_join_keys(df, computer_cols=["src_computer", "resolved_computer"], user_cols=[])

    valid = df.filter(
        F.col("time").isNotNull() &
        F.col("src_computer_key").isNotNull()
    )
    kept = valid.count()
    dropped = bronze_count - kept
    logger.info(f"  dns: kept={kept:,}, dropped={dropped:,}")
    _reconcile("dns", bronze_count, kept, dropped)

    out_path = SILVER_DIR / "dns"
    valid.write.mode("overwrite").parquet(str(out_path))
    return kept


def transform_flows(spark: SparkSession) -> int:
    """Silver flows: join keys, drop nulls."""
    bronze_path = BRONZE_DIR / "flows"
    df = spark.read.parquet(str(bronze_path))
    bronze_count = df.count()

    df = _add_join_keys(df, computer_cols=["src_computer", "dst_computer"], user_cols=[])

    valid = df.filter(
        F.col("time").isNotNull() &
        F.col("src_computer_key").isNotNull() &
        F.col("dst_computer_key").isNotNull()
    )
    kept = valid.count()
    dropped = bronze_count - kept
    logger.info(f"  flows: kept={kept:,}, dropped={dropped:,}")
    _reconcile("flows", bronze_count, kept, dropped)

    out_path = SILVER_DIR / "flows"
    valid.write.mode("overwrite").parquet(str(out_path))
    return kept


def transform_proc(spark: SparkSession) -> int:
    """Silver proc: join keys, drop nulls."""
    bronze_path = BRONZE_DIR / "proc"
    df = spark.read.parquet(str(bronze_path))
    bronze_count = df.count()

    df = _add_join_keys(df, computer_cols=["computer"], user_cols=["user"])

    valid = df.filter(
        F.col("time").isNotNull() &
        F.col("computer_key").isNotNull()
    )
    kept = valid.count()
    dropped = bronze_count - kept
    logger.info(f"  proc: kept={kept:,}, dropped={dropped:,}")
    _reconcile("proc", bronze_count, kept, dropped)

    out_path = SILVER_DIR / "proc"
    valid.write.mode("overwrite").parquet(str(out_path))
    return kept


def transform_redteam(spark: SparkSession) -> int:
    """Silver redteam: join keys, drop nulls."""
    bronze_path = BRONZE_DIR / "redteam"
    df = spark.read.parquet(str(bronze_path))
    bronze_count = df.count()

    df = _add_join_keys(df,
                        computer_cols=["src_computer", "dst_computer"],
                        user_cols=["user"])

    valid = df.filter(
        F.col("time").isNotNull() &
        F.col("src_computer_key").isNotNull()
    )
    kept = valid.count()
    dropped = bronze_count - kept
    logger.info(f"  redteam: kept={kept:,}, dropped={dropped:,}")
    _reconcile("redteam", bronze_count, kept, dropped)

    out_path = SILVER_DIR / "redteam"
    valid.write.mode("overwrite").parquet(str(out_path))
    return kept


def run_silver(spark: SparkSession, sources: list = None) -> dict:
    """Run Silver transformations for specified sources (or all)."""
    SILVER_DIR.mkdir(parents=True, exist_ok=True)
    all_funcs = [
        ("auth", transform_auth),
        ("dns", transform_dns),
        ("flows", transform_flows),
        ("proc", transform_proc),
        ("redteam", transform_redteam),
    ]
    if sources:
        funcs = [(name, f) for name, f in all_funcs if name in sources]
    else:
        funcs = all_funcs

    counts = {}
    for name, func in funcs:
        logger.info(f"Silver transformation: {name}")
        counts[name] = func(spark)
    return counts


if __name__ == "__main__":
    import argparse
    from src.utils.spark_session import get_spark_session
    parser = argparse.ArgumentParser(description="Run Silver transformations.")
    parser.add_argument("--sources", nargs="+", default=None, help="Sources to transform")
    args = parser.parse_args()

    spark = get_spark_session("SilverTransformation")
    run_silver(spark, sources=args.sources)
    spark.stop()

